# -*- coding: utf-8 -*-
from datetime import datetime
from sys import stderr, version

from nginx_parse_emit.emit import (
    upsert_redirect_to_443_block,
    upsert_ssl_cert_to_443_block,
)
from nginxparser import dumps
from offregister_fab_utils.fs import cmd_avail
from patchwork.files import exists

from offregister_certbot.shared import install

if version[0] == "2":
    from itertools import ifilter as filter
    from itertools import imap as map

    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO
else:
    from io import StringIO

from functools import partial
from os import remove
from sys import modules
from tempfile import mkstemp

import offregister_nginx_static.ubuntu as nginx
from offregister_fab_utils.ubuntu.systemd import restart_systemd

from offregister_certbot import get_logger

logger = get_logger(modules[__name__].__name__)


def install0(c, **kwargs):
    """
    :param c: Connection
    :type c: ```fabric.connection.Connection```
    """
    return install(c)


def add_cert1(c, domains, email, server="nginx", **kwargs):
    """add_cert1 gets a new LetsEncrypt HTTPS certificate using certbot.
    Because we don't trust the nginx module, we do this process:
    0. move conf(s) for domain(s) to sites-disabled
    1. create new conf(s) for domain(s) in sites-enabled, that point to temporary wwwroot
    2. use certbot to request new certificate
    3. restore previous conf

    :param c: Connection
    :type c: ```fabric.connection.Connection```
    """

    if server != "nginx":
        logger.warning("Not tested with non nginx: {server}".format(server=server))

    sites_enabled = kwargs.get("sites-enabled", "/etc/nginx/sites-enabled")
    sites_disabled = kwargs.get("sites-disabled", "/etc/nginx/sites-disabled")
    c.sudo("mkdir -p {sites_disabled}".format(sites_disabled=sites_disabled))

    cmd = partial(
        c.sudo,
        user=kwargs.get("as_user", "root"),
        # group=kwargs.get("as_group", "root"),
    )

    if not cmd_avail(c, "nginx") and not exists(c, runner=cmd, path="/usr/sbin/nginx"):
        raise EnvironmentError("nginx is not installed | not found in PATH")

    if not exists(c, runner=cmd, path=sites_enabled):
        raise EnvironmentError('No confs found in "{}"'.format(sites_enabled))

    _grep_conf = "grep -lER {pat} {sites_enabled}".format(
        pat=" -e "
        + " -e ".join(
            "'server_name[[:space:]]+{domain}'".format(domain=domain)
            for domain in domains
        )
        if len(domains) > 0
        else "",
        sites_enabled=sites_enabled,
    )

    confs = cmd(_grep_conf, warn=True)

    if confs.exited != 0:
        stderr.write(confs.stderr)
        raise EnvironmentError(
            "grep failed with: {}. Failed command: {}".format(confs, _grep_conf)
        )

    elif not confs:
        # print(_grep_conf, file=sys.stderr)
        raise ReferenceError("No confs found matching domains searched for")

    confs = [
        s.rstrip().replace(sites_enabled + "/", "") for s in confs.stdout.split("\n")
    ]

    cmd(
        "mv '{sites_enabled}/'{confs} '{sites_disabled}/'".format(
            sites_enabled=sites_enabled,
            confs="{{{confs}}}".format(confs=",".join(confs))
            if len(confs) > 1
            else "".join(confs),
            sites_disabled=sites_disabled,
        )
    )

    def apply_conf(domain):
        root = c.sudo("mktemp -d --suffix .nginx").stdout.strip()
        assert root != "/"
        nginx.setup_custom_conf2(
            c,
            nginx_conf="static.conf",
            SERVER_NAME=domain,
            WWWROOT=root,
            conf_remote_filename="{}/{}".format(
                sites_enabled, domain.replace("/", "-")
            ),
            skip_nginx_restart=True,
        )
        cmd("touch {root}/index.html && chmod -R 755 {root}".format(root=root))
        return root

    static_dirs = tuple(map(apply_conf, domains))

    def exclude_valid_certs(domain):
        cert_details = c.sudo(
            "certbot certificates --cert-name {domain}".format(domain=domain)
        ).stdout

        if "Expiry Date" not in cert_details:
            return domain
        elif "(VALID" not in cert_details:
            return domain

        cert_expiry = next(
            map(
                lambda s: s.partition(":")[2].rpartition("(")[0].strip(),
                filter(
                    lambda s: s.lstrip().startswith("Expiry Date"),
                    cert_details.split("\n"),
                ),
            ),
            None,
        )
        if cert_expiry is None:
            return domain
        cert_expiry = datetime.strptime(cert_expiry, "%Y-%m-%d %H:%M:%S+00:00")
        if (cert_expiry - datetime.now()).days < 30:
            return domain
        return None

    domains = tuple(_f for _f in map(exclude_valid_certs, domains) if _f)

    if domains:
        restart_systemd(c, "nginx")
        cmd(
            "certbot certonly {email} --webroot {webroots} {domains} --agree-tos --no-eff-email".format(
                email="-m '{email}'".format(email=email),
                webroots=" ".join("-w '{}'".format(wr) for wr in static_dirs),
                domains=" ".join("-d '{}'".format(domain) for domain in domains),
            )
        )
        cmd("rm -rf {}/*nginx".format(static_dirs[0][: static_dirs[0].rfind("/")]))
        cmd(
            "rm -f {}".format(
                " ".join(
                    "{}/{}".format(
                        sites_enabled,
                        domain
                        if domain.endswith(".conf")
                        else "{domain}.conf".format(domain=domain),
                    )
                    for domain in domains
                )
            )
        )

    cmd(
        "mv '{sites_disabled}/'{confs} '{sites_enabled}/'".format(
            sites_enabled=sites_enabled,
            confs="{{{confs}}}".format(confs=",".join(confs))
            if len(confs) > 1
            else "{confs}".format(confs="".join(confs)),
            sites_disabled=sites_disabled,
        )
    )

    return restart_systemd(c, "nginx")  # reload didn't work :(


def apply_cert2(c, domains, use_sudo=True, **kwargs):
    """
    :param c: Connection
    :type c: ```fabric.connection.Connection```
    """
    certs_dirname = frozenset(
        d
        for d in c.sudo("ls -AQlx /etc/letsencrypt/live").stdout.split('"')
        if len(d.strip())
    )

    def apply_cert(domain):
        if domain.endswith(".conf"):
            domain = domain[: len(".conf") - 2]
        assert domain in certs_dirname, "{domain} doesn't have certs generated".format(
            domain=domain
        )
        conf_name = "/etc/nginx/sites-enabled/{nginx_conf}.conf".format(
            nginx_conf=domain
        )
        # cStringIO.StringIO, StringIO.StringIO, TemporaryFile, SpooledTemporaryFile all failed :(
        tempfile = mkstemp(domain)[1]
        c.get(remote=conf_name, local=tempfile)

        updated_conf = upsert_ssl_cert_to_443_block(
            conf_file=upsert_redirect_to_443_block(
                conf_file=tempfile, server_name=domain
            ),
            server_name=domain,
            ssl_certificate="/etc/letsencrypt/live/{domain}/fullchain.pem".format(
                domain=domain
            ),
            ssl_certificate_key="/etc/letsencrypt/live/{domain}/privkey.pem".format(
                domain=domain
            ),
        )

        remove(tempfile)

        sio1 = StringIO()
        sio1.write(dumps(updated_conf))
        sio1.seek(0)
        c.put(sio1, conf_name)  # use_sudo=use_sudo)
        return conf_name

    r = tuple(map(apply_cert, domains))

    restart_systemd(c, "nginx")
    return {"updated_ssl_info": r}


__all__ = ["install0", "add_cert1", "apply_cert2"]
