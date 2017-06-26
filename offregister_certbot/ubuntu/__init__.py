from sys import modules

from fabric.operations import _run_command, sudo

from offregister_fab_utils.apt import apt_depends

from offregister_app_push import get_logger

logger = get_logger(modules[__name__].__name__)


def install0(**kwargs):
    sudo('add-apt-repository -y ppa:certbot/certbot')
    apt_depends('certbot', 'python-certbot-nginx')


def add_cert1(webroots, domains, email, server='nginx', **kwargs):
    if server != 'nginx':
        raise NotImplementedError(server)

    return _run_command(
        'certbot certonly {email} --webroot {webroots} {domains} --agree-tos --no-eff-email'.format(
            email="-m '{email}'".format(email=email),
            webroots=' '.join("-w '{}'".format(wr) for wr in webroots),
            domains=' '.join("-d '{}'".format(domain) for domain in domains)
        ),
        user=kwargs.get('as_user', 'root'), group=kwargs.get('as_group', 'root'), sudo=True
    )
