# pylint: disable=missing-docstring
import traceback

import cachetools
import requests

from haas_proxy import constants


class Balancer():
    """
    Handles "load-balancing" of proxies between multiple running honeypots.
    We call HTTP GET where we receive randomly assigned honeypot for 1H.
    """

    api_url = None
    # Expiring cache for API result, expires in 1h.
    cache = cachetools.TTLCache(1, constants.DEFAULT_BALANCER_CHECK_INTERVAL)
    CACHE_KEY = 'API_RESP'

    def __init__(self, api_url):
        self.api_url = api_url

    def load_api(self):
        """
        Returns cached API response or get's data from API.
        """
        cached_resp = self.cache.get(self.CACHE_KEY)
        if cached_resp is None:
            try:
                resp = requests.api.get(self.api_url)
            # pylint: disable=broad-except
            except Exception:
                traceback.print_exc()
                return None

            if resp.status_code != 200:
                print("API returned invalid response: {}".format(resp.text))
                return None

            self.cache[self.CACHE_KEY] = cached_resp = resp.json()

        print("Using haas server: {}".format(cached_resp))
        return cached_resp

    @property
    def host(self):
        """
        Returns host of honeypot.
        """
        api_resp = self.load_api()
        # load_api() may return None if there was error loading the API.
        if api_resp is None:
            return constants.DEFAULT_HONEYPOT_HOST

        # in case someone breaks our balancer API to return wrong JSON.
        api_host = api_resp.get('host')
        if api_host is None:
            return constants.DEFAULT_HONEYPOT_HOST

        return api_host

    @property
    def port(self):
        """
        Returns port of honeypot.
        """
        api_resp = self.load_api()
        # load_api() may return None if there was error loading the API.
        if api_resp is None:
            return constants.DEFAULT_HONEYPOT_PORT

        # in case someone breaks our balancer API to return wrong JSON.
        api_port = api_resp.get('port')
        if api_port is None:
            return constants.DEFAULT_HONEYPOT_PORT

        return api_port
