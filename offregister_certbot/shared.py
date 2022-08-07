from offregister_fab_utils.apt import apt_depends
from offregister_fab_utils.fs import cmd_avail


def install(c):
    """
    :param c: Connection
    :type c: ```fabric.connection.Connection```
    """
    if cmd_avail(c, "certbot"):
        return "certbot already installed"
    uname = c.run("uname -v").stdout.rstrip()
    dist_version = float(c.run("lsb_release -rs", hide=True).stdout.rstrip())
    is_debian = "Debian" in uname
    is_ubuntu = "Ubuntu" in uname
    if is_debian or is_ubuntu:
        apt_depends(
            c,
            "certbot",
            "python{}-certbot-nginx".format(
                "3"
                if is_ubuntu
                and dist_version >= 20.04
                or is_debian
                and dist_version >= 10
                else ""
            ),
        )
    else:
        raise NotImplementedError()


__all__ = ["install"]
