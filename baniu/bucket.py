# coding: utf-8
#
# xiaoyu <xiaokong1937@gmail.com>
#
# 2015/01/19
#
"""
Bucket of Qiniu CDN.

"""
import datetime
import urllib
import urlparse
from base64 import urlsafe_b64encode

from base import QiniuClient, TokenAuth, ApiError

SUPPORTED_ACTIONS = set(["copy", "stat", "move", "delete"])


def q(value, safe='/'):
    """
    Urlencode value.
    """
    value = encode_utf8(value)
    if isinstance(value, str):
        return urllib.quote(value, safe)
    else:
        return value


def encode_utf8(value):
    """
    Encode value to utf-8 str.
    """
    if isinstance(value, unicode):
        value = value.encode('utf8')
    return value


class Bucket(QiniuClient):
    """
    Bucket manager for Qiniu CDN.

    :param bucket_name: your qiniu bucket name.
    :param apikey: your qiniu apikey.
    :param apisecret: your qiniu apisecret.
    :param bucket_domain: domain of your bucket, including http scheme and
                          netloc, without the last `/`, e.g:
                          http://3217uo.com1.z0.glb.clouddn.com
    :param allowed_host: one white-list host of your bucket.
        If `anti-bandwith-theft` was not set, leave blank of this param.
    """
    def __init__(self, bucket_name, apikey, apisecret,
                 bucket_domain='', allowed_host=''):
        super(Bucket, self).__init__(apikey, apisecret)
        if not bucket_name:
            raise ApiError(-1, "Invalid Bucket Name.")
        self.bucket_name = bucket_name
        self.host = 'rs.qiniu.com'
        self._set_headers(self.host)
        self.bucket_domain = bucket_domain
        self.allowed_host = allowed_host

    def save(self, file_key, filelike, **kwargs):
        """
        Save file content to file_key.

        Kwargs could be args of PUT policy.
        """
        return super(Bucket, self).chunk_upload(
            filelike, self.bucket_name, key=file_key, **kwargs
        )

    def generate_url(self, file_key):
        """
        Generate  url for the file specified by the file_key.
        """
        return "{}/{}".format(self.bucket_domain, q(file_key))

    def get_object_contents(self, file_key, chunk_size=None):
        """
        Get contents for the file specified by the file_key.
        """
        origin_url = self.generate_url(file_key)
        download_url = self._get_download_url(origin_url)
        token = self.download_token(download_url)
        params = {
            "token": token
        }
        object_url = "{}&{}".format(download_url, urllib.urlencode(params))
        parsed_url = urlparse.urlparse(object_url)
        host = parsed_url.netloc
        # Bugfix: `anti-bandwidth-theft` needs a whitelist host.
        self.r.headers.update(
            {'Referer': 'http://{}/'.format(self.allowed_host)})
        if chunk_size:
            resp = self._request(object_url, method="GET",
                                 host=host, stream=True)
            if resp.status_code == 403:
                raise ApiError(403, 'Forbidden. Private domain or '
                               'protected domain need a valid allowed_host.')
            return resp.iter_content(chunk_size=chunk_size)
        resp = self._request(object_url, method="GET", host=host)
        if resp.status_code == 403:
            raise ApiError(403, 'Forbidden. Private domain or '
                                'protected domain need a valid allowed_host.')
        return resp.content

    def stat(self, file_key):
        """
        Get status of an object.

        Params:
            file_key: a string refers to the key for the file.

        Return:
            dict like bellow.

            {
                "fsize": int,

                "hash": str(fileETag),

                "mimeType": str(MIMEType),

                "putTime": datetime.datetime(....)

            }
        """
        resp = self._do(file_key, action="stat")
        stat_json = resp.json()
        put_time = stat_json.get('putTime')
        if put_time:
            put_time = datetime.datetime.fromtimestamp(put_time / 1000000)
            stat_json['putTime'] = put_time
        return stat_json

    def copy(self, from_file_key, to_file_key, action="copy"):
        return self._do(from_file_key, to_file_key)

    def move(self, from_file_key, to_file_key):
        return self._do(from_file_key, to_file_key, action="move")

    def delete(self, file_key):
        return self._do(file_key, action="delete")

    def batch(self, **kwargs):
        """
        Batch operate the requested resource.

        kwargs may be :
        {

            "stat": ["file_key1", "file_key2"], # list or str

            "copy": [("from_f", "to_f"), ...], # list with tuple or tupple

        }
        """
        body = []
        opts = kwargs.copy()
        kwargs_valid = False
        for key in opts:
            if key in SUPPORTED_ACTIONS:
                kwargs_valid = True
                break
        if not kwargs_valid:
            raise ApiError(-6, "Kwargs for batch operation not valid.")

        for key in opts:
            if key in ["stat", "delete"]:
                obj = opts[key]
                if isinstance(obj, str):
                    body.append("/{}/{}".format(key, self._encode(obj)))
                elif isinstance(obj, list):
                    body.extend(["/{}/{}".format(key, self._encode(obj_))
                                 for obj_ in obj])
                else:
                    raise ApiError(-4, "String or list object required for"
                                       " batch stat or batch delete.")
            elif key in ["copy", "move"]:
                obj = opts[key]
                if isinstance(obj, tuple):
                    body.append("/{}/{}/{}".format(
                        key, self._encode(obj[0]), self._encode(obj[1])))
                elif isinstance(obj, list):
                    for obj_ in obj:
                        if not isinstance(obj_, tuple):
                            raise ApiError(-4, "Tuple object required for "
                                               "batch copy or batch move")
                        body.append("/{}/{}/{}".format(
                            key, self._encode(obj_[0]), self._encode(obj_[1])))
        body_str = "&".join("op={}".format(urllib.quote(ops)) for ops in body)
        batch_url = "http://{}/batch".format(self.host)
        resp = self._request(batch_url, data=body_str)
        return resp

    def list(self, **kwargs):
        """
        List files of a bucket.

        Kwargs may have the following optional keys:

            "limit": an int object small than 1000.

            "prefix": a string for the prefix of file_keys.

            "delimiter": a string for a delimiter of directory.

            "marker": marker of last list request.
        """
        default_params = set(["limit", "prefix", "delimiter", "marker"])
        opts = self._copy_params(kwargs, default_params)
        params = {"bucket": self.bucket_name}
        if "limit" in opts:
            limit = opts.get("limit")
            if not isinstance(limit, int):
                limit = 1000
            limit = max(min(1000, limit), 1)
            opts.update({"limit": limit})
        params.update(opts)
        host = "rsf.qbox.me"
        list_url = "http://{}/list?{}".format(host, urllib.urlencode(params))
        resp = self._request(list_url, host=host, method="POST")
        return resp

    def fetch(self, from_uri, to_file_key):
        """
        Fetch a remote resource to a bucket file.
        """
        uri = urlsafe_b64encode(from_uri)
        to_file_key = self._encode(to_file_key)
        host = "iovip.qbox.me"
        fetch_url = "http://{}/fetch/{}/to/{}".format(host, uri, to_file_key)
        resp = self._request(fetch_url, host=host)
        return resp

    def prefetch(self, file_key):
        """
        Prefetch a remote resource to a bucket file.

        Note:
            You should set prefetch url first. See the `qiniu API docs <http
            ://developer.qiniu.com/docs/v6/api/reference/rs/prefe
            tch.html>`_ for detail.
        """
        file_key = self._encode(file_key)
        host = "iovip.qbox.me"
        prefetch_url = "http://{}/prefetch/{}".format(host, file_key)
        resp = self._request(prefetch_url, host=host)
        return resp

    def change_mimetype(self, file_key, mimetype):
        """
        Change the mimetype of a file.
        """
        # TODO: check if mimetype is valid.
        mimetype = urlsafe_b64encode(mimetype)
        host = "rs.qiniu.com"
        chgm_url = "http://{}/chgm/{}/mime/{}".format(
            host, self._encode(file_key), mimetype)
        resp = self._request(chgm_url, host=host)
        return resp

    def save_as(self, resource_uri, file_key):
        """
        Save the handled resource to a new file.
        """
        final_url = self._get_saveas_url(resource_uri, file_key)
        parsed_url = urlparse.urlparse(final_url)
        host = parsed_url.netloc
        resp = self._request(final_url, method="GET", host=host)
        return resp

    def pfop(self, file_key, fops, notify_url, pipeline='', force=0):
        """
        Persistent file operations.

        Returns:
        {
            "persistentId": <persistentId int64>
        }
        """
        params = {
            "bucket": self.bucket_name,
            "key": file_key,
            "fops": fops,
            "notifyURL": notify_url,
            "force": force,
        }
        if pipeline:
            params.update({"pipeline": pipeline})
        host = "api.qiniu.com"
        url = "http://{}/pfop/".format(host)
        resp = self._request(url, host=host, data=params, method="POST")
        return resp

    def get_pfop_status(self, persistent_id):
        """
        Get status of pfop(persistent file operations) with persistent_id got
        from pfop method.

        """
        params = {
            "id": persistent_id
        }
        host = "api.qiniu.com"
        url = "http://{}/status/get/prefop".format(host)
        resp = self._request(url, host=host, params=params, method="GET")
        return resp

    #  Helper functions -----------------------------------------------------
    def _get_saveas_url(self, resource_uri, file_key):
        """
        Get the saveas url of a file.

        Note this function do not trigger the real `save as` action. If you
        want to save the file, use `save_as` function instead.
        """
        parsed_uri = urlparse.urlparse(resource_uri)
        scheme = "{}://".format(parsed_uri.scheme)
        url = parsed_uri.geturl().replace(scheme, '', 1)
        new_url = "{}|saveas/{}".format(url, self._encode(file_key))
        signing_url = new_url.replace("|", "%7C")
        encoded_sign = self._calc_token(signing_url)
        final_url = "{}{}/sign/{}:{}".format(scheme,
                                             new_url,
                                             self.apikey,
                                             encoded_sign)
        return final_url

    def _copy_params(self, kwargs, default_params):
        """
        Get and update keys of kwargs where keys in default_params.
        """
        ret = {}
        for key in kwargs:
            if key in default_params:
                ret[key] = kwargs[key]
        return ret

    def _do(self, from_file_key, to_file_key='', action="copy"):
        """
        Backend of `copy`, `stat`, `delete`, `move` method.

        """
        from_ = self._encode(from_file_key)
        action_url = "http://{}/{}/{}/{}".format(
            self.host,
            action,
            from_,
            self._encode(to_file_key) if to_file_key else ""
        )
        method = "GET" if action == "stat" else "POST"
        resp = self._request(action_url, method=method)
        return resp

    def _encode(self, file_key):
        """
        Implemention of `EncodedEntryURI`.
        """
        return urlsafe_b64encode("{}:{}".format(self.bucket_name, file_key))

    def _request(self, url, method='POST', host='', data={}, params={},
                 stream=False):
        """
        Request resources.

        Always returns response object but not json decoded dict.
        """
        if not host:
            host = self.host
        self.r.headers.update({"Host": host})
        if method == "POST":
            self.r.headers.update({
                "Content-Type": "application/x-www-form-urlencoded"
            })

        token = self.management_token(url, data)
        auth = TokenAuth('QBox', token)
        resp = self.r._request(url, auth=auth, method=method, params=params,
                               data=data, stream=stream)
        return resp
