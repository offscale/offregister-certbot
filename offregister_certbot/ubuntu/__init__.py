from __future__ import print_function

from datetime import datetime
from platform import python_version_tuple

from nginx_parse_emit.emit import upsert_ssl_cert_to_443_block, upsert_redirect_to_443_block
from nginxparser import dumps

if python_version_tuple()[0] == '2':
    from cStringIO import StringIO
    from itertools import imap, ifilter
else:
    from io import StringIO

    imap = map
    ifilter = filter

from functools import partial
from itertools import imap
from os import remove
from sys import modules
from tempfile import mkstemp

import offregister_nginx_static.ubuntu as nginx
from fabric.context_managers import cd
from fabric.operations import _run_command, sudo, get, put, run

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
        pat=' -e ' + ' -e '.join("'server_name[[:space:]]+{domain}'".format(domain=domain) for domain in domains)
        if len(domains) > 0 else '',
        sites_enabled=sites_enabled)

    confs = cmd(_grep_conf, warn_only=True)

    if confs.failed:
        raise EnvironmentError('grep failed with: {}. Failed command: {}'.format(confs, _grep_conf))

    elif not confs:
        # print(_grep_conf, file=sys.stderr)
        raise ReferenceError('No confs found matching domains searched for')

    confs = map(lambda s: s.rstrip().replace(sites_enabled + '/', ''), confs.split('\n'))

    cmd("mv '{sites_enabled}/'{{{confs}}} '{sites_disabled}/'".format(sites_enabled=sites_enabled,
                                                                      confs=','.join(confs),
                                                                      sites_disabled=sites_disabled))

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

    def exclude_valid_certs(domain):
        cert_details = sudo('certbot certificates --cert-name {domain}'.format(domain=domain))

        if 'Expiry Date' not in cert_details:
            return domain
        elif '(VALID' not in cert_details:
            return domain

        cert_expiry = next(imap(lambda s: s.partition(':')[2].rpartition('(')[0].strip(),
                                ifilter(lambda s: s.lstrip().startswith('Expiry Date'),
                                        cert_details.split('\n'))), None)
        if cert_expiry is None:
            return domain
        cert_expiry = datetime.strptime(cert_expiry, '%Y-%m-%d %H:%M:%S+00:00')
        if (cert_expiry - datetime.now()).days < 30:
            return domain
        return None

    domains = tuple(filter(None, map(exclude_valid_certs, domains)))

    if domains:
        cmd('certbot certonly {email} --webroot {webroots} {domains} --agree-tos --no-eff-email'.format(
            email="-m '{email}'".format(email=email),
            webroots=' '.join("-w '{}'".format(wr) for wr in static_dirs),
            domains=' '.join("-d '{}'".format(domain) for domain in domains)
        ))
        cmd('rm -rf {}/*nginx'.format(static_dirs[0][:static_dirs[0].rfind('/')]))
        cmd('rm {}'.format(' '.join('{}/{}'.format(sites_enabled, domain) for domain in domains)))

    cmd("mv '{sites_disabled}/'{{{confs}}} '{sites_enabled}/'".format(sites_enabled=sites_enabled,
                                                                      confs=','.join(confs),
                                                                      sites_disabled=sites_disabled))

    return restart_systemd('nginx')  # reload didn't work :(


def apply_cert2(domains, use_sudo=True, **kwargs):
    certs_dirname = frozenset(d for d in sudo('ls -AQlx /etc/letsencrypt/live').split('"')
                              if len(d.strip()))

    def apply_cert(domain):
        if domain.endswith('.conf'):
            domain = domain[:len('.conf') - 2]
        assert domain in certs_dirname, '{domain} doesn\'t have certs generated'.format(domain=domain)
        conf_name = '/etc/nginx/sites-enabled/{nginx_conf}.conf'.format(nginx_conf=domain)
        # cStringIO.StringIO, StringIO.StringIO, TemporaryFile, SpooledTemporaryFile all failed :(
        tempfile = mkstemp(domain)[1]
        get(remote_path=conf_name, local_path=tempfile, use_sudo=use_sudo)

        updated_conf = upsert_ssl_cert_to_443_block(
            conf_file=upsert_redirect_to_443_block(conf_file=tempfile, server_name=domain),
            server_name=domain,
            ssl_certificate='/etc/letsencrypt/live/{domain}/fullchain.pem'.format(domain=domain),
            ssl_certificate_key='/etc/letsencrypt/live/{domain}/privkey.pem'.format(domain=domain)
        )

        remove(tempfile)

        sio1 = StringIO()
        sio1.write(dumps(updated_conf))
        sio1.seek(0)
        put(sio1, conf_name, use_sudo=use_sudo)
        return conf_name

    r = tuple(imap(apply_cert, domains))

    restart_systemd('nginx')
    return {'updated_ssl_info': r}
