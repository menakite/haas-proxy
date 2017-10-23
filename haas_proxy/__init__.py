"""
Proxy for project Honepot as a Service by CZ.NIC. This proxy is needed to
tag SSH activity with your account ID so you can watch your log online.

Script has hardcoded address of honeypot running at CZ.NIC. It shouldn't
be changed but if does or you need to use proxy, use optional arguments
`--honeypot-host` and `--honeypot-port`.

Script contains one pre-generated key. If you want to use own, create one
with the following command:

    $ ssh-keygen -t rsa -b 4096

Store it in some path and then pass it as arguments:

    --public-key "$(< /path/id_rsa.pub)" --private-key "$(< /path/id_rsa)"

Example usage:

    $ python -m haas_proxy [TWISTED OPTIONS] haas_proxy [HAAS OPTIONS]
    $ python -m haas_proxy -l /tmp/haas.log --pidfile /tmp/haas.pid haas_proxy --device-token XXX

Note that there is not used script `twistd` but `python -m haas_proxy`. It's
because you would need to pass PYTHONPATH by hand which is not comfortable.
The rest of arguments works the same way.
"""

from haas_proxy import constants
from haas_proxy.proxy import ProxyService
