from functools import partial
from itertools import imap
from sys import modules

from fabric.context_managers import cd
from fabric.operations import _run_command, sudo, run

from offregister_fab_utils.apt import apt_depends
from offregister_fab_utils.ubuntu.systemd import restart_systemd
import offregister_nginx_static.ubuntu as nginx

from offregister_certbot import get_logger

logger = get_logger(modules[__name__].__name__)


def install0(**kwargs):
    sudo('add-apt-repository -y ppa:certbot/certbot')
    apt_depends('certbot', 'python-certbot-nginx')


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

    cmd = partial(_run_command, user=kwargs.get('as_user', 'root'), group=kwargs.get('as_group', 'root'),
                  shell_escape=False, sudo=True)
    confs = cmd('grep -lER {pat} {sites_enabled}'.format(
        pat='-e '.join("'server_name[[:space:]]+{domain}'".format(domain=domain) for domain in domains),
        sites_enabled=sites_enabled
    ))
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
    cmd('rm {}'.format('{}/{} '.format(sites_enabled, domain) for domain in domains))

    cmd(';'.join("mv '{conf}' {sites_enabled}/".format(conf=conf.replace(sites_enabled, sites_disabled),
                                                       sites_disabled=sites_disabled,
                                                       sites_enabled=sites_enabled)
                 for conf in confs.split('\n')))
    return restart_systemd('nginx')  # reload didn't work :(
