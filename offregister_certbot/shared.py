from fabric.operations import run, sudo
from offregister_fab_utils.apt import apt_depends
from offregister_fab_utils.fs import cmd_avail


def install():
    if cmd_avail("certbot"):
        return "certbot already installed"
    uname = run("uname -v")
    if "Ubuntu" in uname:
        dist_version = float(run("lsb_release -rs", quiet=True))
        py_dep = "python-certbot-nginx"
        if dist_version < 20.04:
            sudo("add-apt-repository -y ppa:certbot/certbot")
        else:
            py_dep = "python3-certbot-nginx"
        apt_depends("certbot", py_dep)
    elif "Debian" in uname:
        sudo("apt-get install -y certbot python-certbot-nginx -t stretch-backports")
    else:
        raise NotImplementedError()
