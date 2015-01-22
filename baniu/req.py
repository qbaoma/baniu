# coding: utf-8
#
# xiaoyu <xiaokong1937@gmail.com>
#
# 2014/12/15
#
"""
Base Requests Client.

Requests backend for baniu.

"""
import requests


class BaseRequestsClient(object):
    def __init__(self, headers={}, cookies='', host='', referer=''):
        self.headers = headers
        self.cookies = cookies
        self.host = host
        self.referer = referer or 'http://%s/' % self.host
        self._set_headers()

    def _set_headers(self):
        """
        Set request headers.
        """
        self.headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Host': self.host,
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/'
                          '537.36 (KHTML, like Gecko) Chrome/30.0.1599.'
                          '101 Safari/537.36',
        }

    def _request(self,
                 url=None,
                 method=None,
                 headers=None,
                 files=None,
                 stream=False,
                 data=None,
                 params=None,
                 auth=None,
                 cookies=None,
                 hooks=None,
                 verify=False):

        headers = self.headers if headers is None else headers
        cookies = self.cookies if cookies is None else cookies
        if method is None:
            method = 'GET' if data is None else 'POST'
            method = 'POST' if files is not None else method

        # Proxy for requests, used for http_debug.
        # Note: by this way, you can use debug tool after its proxy set
        # to 192.168.1.122:8888 (like fiddler2 ).
        # Default: None.
        http_debug = False

        if http_debug:
            http_proxy = 'http://192.168.1.122:8888'
            https_proxy = 'http://192.168.1.122:8888'
            proxyDict = {'http': http_proxy,
                         'https': https_proxy}
        else:
            proxyDict = None

        if method == 'GET':
            resp = requests.get(url, params=params, headers=headers,
                                cookies=cookies, verify=verify, auth=auth,
                                proxies=proxyDict, stream=stream)
        else:
            resp = requests.post(url, params=params, data=data,
                                 headers=headers, cookies=cookies,
                                 verify=verify, files=files, auth=auth,
                                 proxies=proxyDict, stream=stream)
        self.cookies = cookies
        return resp
