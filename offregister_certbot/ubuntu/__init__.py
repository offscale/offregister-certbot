from __future__ import print_function

import sys
from cStringIO import StringIO
from functools import partial
from itertools import imap
from os import remove
from sys import modules
from tempfile import mkstemp

import offregister_nginx_static.ubuntu as nginx
from fabric.context_managers import cd
from fabric.contrib.files import exists
from fabric.operations import _run_command, sudo, get, put, run
from nginx_parse_emit import emit as nginx_emit
from nginx_parse_emit.utils import apply_attributes
from nginxparser import dumps, load, loads
from offregister_fab_utils.apt import apt_depends
from offregister_fab_utils.fs import cmd_avail
from offregister_fab_utils.ubuntu.systemd import restart_systemd

from offregister_certbot import get_logger

logger = get_logger(modules[__name__].__name__)


def install0(**kwargs):
    if cmd_avail('certbot'):
        return 'certbot already installed'
    uname = run('uname -v')
    if 'Ubuntu' in uname:
        sudo('add-apt-repository -y ppa:certbot/certbot')
        apt_depends('certbot', 'python-certbot-nginx')
    elif 'Debian' in uname:
        sudo('apt-get install -y certbot python-certbot-nginx -t stretch-backports')
    else:
        raise NotImplementedError()


def add_cert1(domains, email, server='nginx', **kwargs):
    """ add_cert1 gets a new LetsEncrypt HTTPS certificate using certbot.
        Because we don't trust the nginx module, we do this process:
        0. move conf(s) for domain(s) to sites-disabled
        1. create new conf(s) for domain(s) in sites-enabled, that point to temporary wwwroot
        2. use certbot to request new certificate
        3. restore previous conf
    """

    if server != 'nginx':
        logger.warning('Not tested with non nginx: {server}'.format(server=server))

    sites_enabled = kwargs.get('sites-enabled', '/etc/nginx/sites-enabled')
    sites_disabled = kwargs.get('sites-disabled', '/etc/nginx/sites-disabled')
    sudo('mkdir -p {sites_disabled}'.format(sites_disabled=sites_disabled))

    cmd = partial(_run_command, user=kwargs.get('as_user', 'root'), group=kwargs.get('as_group', 'root'),
                  shell_escape=False, sudo=True)

    _grep_conf = 'grep -lER {pat} {sites_enabled}'.format(
        pat='-e '.join("'server_name[[:space:]]+{domain}'".format(domain=domain) for domain in domains),
        sites_enabled=sites_enabled)

    confs = cmd(_grep_conf, warn_only=True)

    if not confs:
        print(_grep_conf, file=sys.stderr)
        raise ReferenceError('No confs found matching domains searched for')

    # Could do the `mv /etc/nginx/sites-enabled/{foo,bar}` syntax instead...
    cmd(';'.join("mv '{conf}' '{sites_disabled}'/".format(conf=conf, sites_disabled=sites_disabled)
                 for conf in confs.split('\n')))

    def apply_conf(domain):
        root = cmd('mktemp -d --suffix .nginx')
        nginx.setup_conf0(nginx_conf='static.conf', SERVER_NAME=domain, WWWROOT=root,
                          conf_remote_filename='{}/{}'.format(sites_enabled, domain.replace('/', '-')),
                          skip_nginx_restart=True)
        with cd(root):
            cmd('touch index.html')
        cmd('chmod -R 755 {root}'.format(root=root))
        return root

    static_dirs = tuple(imap(apply_conf, domains))
    restart_systemd('nginx')  # reload didn't work :(
    cmd('certbot certonly {email} --webroot {webroots} {domains} --agree-tos --no-eff-email'.format(
        email="-m '{email}'".format(email=email),
        webroots=' '.join("-w '{}'".format(wr) for wr in static_dirs),
        domains=' '.join("-d '{}'".format(domain) for domain in domains)
    ))
    cmd('rm -rf {}/*nginx'.format(static_dirs[0][:static_dirs[0].rfind('/')]))
    cmd('rm {}'.format(' '.join('{}/{}'.format(sites_enabled, domain) for domain in domains)))

    cmd(';'.join("mv '{conf}' {sites_enabled}/".format(conf=conf.replace(sites_enabled, sites_disabled),
                                                       sites_disabled=sites_disabled,
                                                       sites_enabled=sites_enabled)
                 for conf in confs.split('\n')))
    return restart_systemd('nginx')  # reload didn't work :(


def apply_cert2(domains, use_sudo=True, **kwargs):
    certs_dirname = frozenset(d for d in sudo('ls -AQlx /etc/letsencrypt/live').split('"') if len(d.strip()))

    def apply_cert(domain):
        assert domain in certs_dirname, '{domain} doesn\'t have certs generated'.format(domain=domain)
        conf_name = '/etc/nginx/sites-enabled/{nginx_conf}'.format(nginx_conf=domain)
        if not conf_name.endswith('.conf') and not exists(conf_name):
            conf_name += '.conf'
        # cStringIO.StringIO, StringIO.StringIO, TemporaryFile, SpooledTemporaryFile all failed :(
        tempfile = mkstemp(domain)[1]
        get(remote_path=conf_name, local_path=tempfile, use_sudo=use_sudo)
        with open(tempfile, 'rt') as f:
            conf = load(f)
        new_conf = apply_attributes(conf,
                                    nginx_emit.secure_attr(
                                        '/etc/letsencrypt/live/{domain}/fullchain.pem'.format(domain=domain),
                                        '/etc/letsencrypt/live/{domain}/privkey.pem'.format(domain=domain)))
        remove(tempfile)

        new_conf = loads(nginx_emit.redirect_block(server_name=domain, port=80)) + new_conf

        sio = StringIO()
        sio.write(dumps(new_conf))
        put(sio, conf_name, use_sudo=use_sudo)
        return conf_name

    r = tuple(imap(apply_cert, domains))

    restart_systemd('nginx')
    return {'updated_ssl_info': r}
