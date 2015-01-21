# coding: utf-8
#
# xiaoyu <xiaokong1937@gmail.com>
#
# 2015/01/09
#
"""
BaseClient of qiniu.

"""
import time
from base64 import urlsafe_b64encode
import hmac
import hashlib
import json
import urllib
import urlparse
import binascii
import Queue
import threading
import StringIO

import requests

from req import BaseRequestsClient

PUT_POLICY = set([
    "insertOnly",
    "saveKey",
    "endUser",
    "returnUrl",
    "returnBody",
    "callbackUrl",
    "callbackHost",
    "callbackBody",
    "callbackBodyType",
    "callbackFetchKey",
    "persistentOps",
    "persistentNotifyUrl",
    "persistentPipeline",
    "fsizeLimit",
    "detectMime",
    "mimeLimit"])

BLOCK_SIZE = 4194304  # 4 MB
CHUNK_SIZE = 256 * 1024  # 256 KB
UPLOAD_THREAD_COUNT = 5
UPLOAD_HOST = 'upload.qiniu.com'

block_queue = Queue.Queue()
ctx_queue = Queue.Queue()
total_uploaded_queue = Queue.Queue(1)
total_uploaded_queue.put(0)


class ApiError(StandardError):
    def __init__(self, error_code, error):
        self.error_code = error_code
        self.error = error
        super(ApiError, self).__init__(error)

    def __str__(self):
        return "{0} : {1}".format(self.error_code, self.error)


class TokenAuth(requests.auth.AuthBase):
    """
    Token Auth.
    """
    def __init__(self, token_key, token):
        self.token_key = token_key
        self.token = token

    def __call__(self, r):
        r.headers['Authorization'] = "{} {}".format(self.token_key, self.token)
        return r


class BaseQiniuClient(object):
    """
    Base Qiniu Client.

    """
    def __init__(self, apikey, apisecret):
        if not apikey or not apisecret:
            raise ApiError(0, "Not a valid key or secret.")
        self.apikey = apikey
        self.apisecret = apisecret
        self.r = BaseRequestsClient()

    def _set_headers(self, host):
        """
        Set HEADERS for requests.

        In this case, we just change the `HOST` field.
        """
        self.r.headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Host': host,
            'User-Agent': 'Baniu Client'
        }

    def _calc_token(self, json_str):
        """
        Calculate token from json encoded string.

        """
        hashed = hmac.new(self.apisecret, json_str, hashlib.sha1)
        return urlsafe_b64encode(hashed.digest())

    def encode_policy(self, scope, maxage=3600, **kwargs):
        """
        Build PUT policy and url-safe base64 encode it.

        """
        policy = {}
        opts = kwargs.copy()
        if not scope:
            raise ApiError(1, "Not a valid scope")
        filekey = opts.get('key', '')
        scope = str(scope) if not filekey else "{0}:{1}".format(scope, filekey)
        if not isinstance(maxage, int):
            maxage = 0
        deadline = int(time.time()) + maxage
        policy.update(dict(scope=scope, deadline=deadline))
        policy.update({key: opts[key] for key in opts if key in PUT_POLICY})
        policy_str = json.dumps(policy, separators=(',', ':'))
        return urlsafe_b64encode(policy_str)

    def upload_token(self, encoded_policy):
        """
        Build upload token from encode_policy.

        """
        encoded_sign = self._calc_token(encoded_policy)
        return "{0}:{1}:{2}".format(self.apikey, encoded_sign, encoded_policy)

    def download_token(self, download_url):
        """
        Build download token from download url.

        """
        encoded_sign = self._calc_token(download_url)
        return "{0}:{1}".format(self.apikey, encoded_sign)

    def _get_download_url(self, origin_download_url, maxage=3600):
        if not isinstance(maxage, int):
            maxage = 3600
        expire_in = int(time.time()) + maxage
        params = urllib.urlencode({'e': expire_in})
        download_url = "{0}?{1}".format(origin_download_url, params)
        return download_url

    def management_token(self, url, body=""):
        """
        Build management token from  url and body.

        """
        if isinstance(body, dict):
            body = urllib.urlencode(body)
        parsed_url = urlparse.urlparse(url)
        signing_str = "{0}{1}\n{2}".format(
            parsed_url.path,
            "?{}".format(parsed_url.query) if parsed_url.query else "",
            body)
        encoded_sign = self._calc_token(signing_str)
        return "{0}:{1}".format(self.apikey, encoded_sign)

    def upload(self, filelike, scope, key="", maxage=3600, **kwargs):
        raise NotImplementedError

    def chunk_upload(self, filelike, scope, maxage=3600, **kwargs):
        """
        Chunk upload a big file.

        Split the file into 4MB with each piece as a block, and split the
        block into 256KB pieces as chunks. Upload the block and chunks.
        """
        opts = kwargs.copy()
        encoded_policy = self.encode_policy(scope, maxage, **opts)
        upload_token = self.upload_token(encoded_policy)
        self._chunk_upload(filelike, upload_token)
        key = kwargs.get('key')
        filesize = self._get_file_length(filelike)
        resp_json = self._mkfile(filesize, upload_token, key)
        return resp_json

    def _chunk_upload(self, filelike, upload_token):
        """
        Real chunk upload.

        Reimplement this function to upload blocks and chunks.
        """
        raise NotImplementedError

    def _mkfile(self, filesize, token, key=''):
        global ctx_queue
        ctx_list = sorted(dump_queue(ctx_queue))
        host = ctx_list[-1].split("||")[-1]
        ctx_list = [ctx.split("||")[1] for ctx in sorted(ctx_list)]
        mkfile_url = 'http://{}/mkfile/{}/{}'.format(
            host,
            filesize,
            'key/{}'.format(urlsafe_b64encode(key)) if key else '')
        data = ",".join(ctx_list)
        auth = TokenAuth('UpToken', token)
        self.r.headers.update({'Host': host})
        resp = self.r._request(mkfile_url, auth=auth, data=data)
        return resp.json()

    def _block_generator(self, filelike):
        """
        Helper function to yield file block data.
        """
        while True:
            data = filelike.read(BLOCK_SIZE)
            if not data:
                break
            yield data

    def _get_file_length(self, filelike):
        """
        Helper function to get the length of file object.
        """
        # StringIO object has a `len` attribute.
        if hasattr(filelike, 'len'):
            return filelike.len

        # str object has a `__len__` attribute.
        if hasattr(filelike, '__len__'):
            return len(filelike)

        # filelike object.
        if hasattr(filelike, 'seek') and hasattr(filelike, 'tell'):
            filelike.seek(0, 2)
            total_length = filelike.tell()
            filelike.seek(0)
            return total_length


class ChunkUploadMixin(object):
    """
    Mixin for chunk upload.

    You can mix in this class with a threading.Thread class.

    """
    #  Helper functions for chunk upload.
    def _bulk_mkblk(self, block, token, block_index, reporthook=None):
        # Split the file block into chunk.
        auth = TokenAuth("UpToken", token)
        ctx = ''
        crc32 = 0
        block = StringIO.StringIO(block)
        up_host = UPLOAD_HOST
        global ctx_queue
        global total_uploaded_queue

        for i in range(BLOCK_SIZE / CHUNK_SIZE):
            data = block.read(CHUNK_SIZE)
            if not data:
                break
            if i == 0:  # first chunk, make block
                mkblk_url = 'http://{}/mkblk/{}'.format(
                    UPLOAD_HOST,
                    BLOCK_SIZE if block.len >= BLOCK_SIZE else block.len)
                resp = self.r._request(mkblk_url, auth=auth, data=data,
                                       method='POST')
                resp_json = resp.json()
            else:  # upload the rest chunks.
                if not ctx:
                    raise ApiError(-1, "Not a valid ctx.")
                next_chunk_offset = CHUNK_SIZE * i
                bput_url = 'http://{}/bput/{}/{}'.format(up_host,
                                                         ctx,
                                                         next_chunk_offset)
                resp = self.r._request(bput_url, auth=auth, data=data)
                resp_json = resp.json()
            # Get `ctx` from resp_json
            ctx = resp_json.get('ctx')
            calc_crc32 = binascii.crc32(data) & 0xffffffff
            crc32 = resp_json.get('crc32')
            if crc32 != calc_crc32:
                # TODO: reupload the failed chunk.
                raise ApiError(-2, "CRC32 check failed.")
            up_host = resp_json.get('host', UPLOAD_HOST)
            up_host = urlparse.urlparse(up_host).netloc

            # Report the current upload progress.
            if reporthook:
                if total_uploaded_queue.qsize() > 0:
                    uploaded = total_uploaded_queue.get()
                else:
                    uploaded = 0
                uploaded += len(data)
                total_uploaded_queue.put(uploaded)
                reporthook(uploaded)
        ctx_str = "{}||{}||{}".format(block_index, ctx, up_host)
        ctx_queue.put(ctx_str)


class ThreadingChunkUpload(ChunkUploadMixin, threading.Thread):
    def __init__(self, token, reporthook=None):
        self.r = BaseRequestsClient(host=UPLOAD_HOST)
        self.r.headers.update({'Content-Type': 'application/octet-stream'})
        self.token = token
        self.reporthook = reporthook
        threading.Thread.__init__(self)

    def run(self):
        global block_queue
        while block_queue.qsize() > 0:
            block_data = block_queue.get()
            block = block_data.get('block')
            block_index = block_data.get('index')
            self._bulk_mkblk(block, self.token, block_index,
                             reporthook=self.reporthook)


class QiniuClient(BaseQiniuClient):

    def upload(self, filelike, scope, maxage=3600, **kwargs):
        """
        Upload a filelike object to Qiniu.

        `filelike` is a filelike object.
        You should specify the PUT policy in kwargs.

        """
        self._set_headers(UPLOAD_HOST)
        opts = kwargs.copy()
        params = {}

        encoded_policy = self.encode_policy(scope, maxage, **opts)
        upload_token = self.upload_token(encoded_policy)
        crc = binascii.crc32(filelike)
        params.update({key: opts[key] for key in opts
                       if key not in PUT_POLICY})
        params.update({
            'token': upload_token,
            'crc32': crc,
        })
        files = {'file': ('fakefilename', filelike)}

        resp = self.r._request("http://{}/".format(UPLOAD_HOST),
                               files=files, data=params)
        if resp.status_code != 200:
            raise ApiError(resp.status_code, resp.json()['error'])
        return resp.json()

    def _chunk_upload(self, filelike, token):
        """
        Split the filelike object into 4MB pieces with a single piece as
        a `block` and pass block, token, and block_index to
        ChunkUploadMixin._bulk_mkblk function.

        About reporthook:
        # Get the total file size::

            self.file_size = self._get_file_length(filelike)

        # define a funtion like::

            def reporthook(uploaded):
                import sys
                percent = int(uploaded * 100 / self.file_size)
                sys.stdout.write("\rUploaded : {:2d} %".format(percent))
                sys.stdout.flush()

        # When create ThreadingChunkUpload instance, pass the reporthook
        function::

            task = ThreadingChunkUpload(token, reporthook=reporthook)

        """
        tasks = []

        for index, block in enumerate(self._block_generator(filelike)):
            block_queue.put({'block': block, 'index': index})

        for i in range(UPLOAD_THREAD_COUNT):
            task = ThreadingChunkUpload(token)
            tasks.append(task)

        for task in tasks:
            task.start()

        for task in tasks:
            task.join()


def dump_queue(queue):
    dumped_list = []
    while queue.qsize() > 0:
        dumped_list.append(queue.get())
    return dumped_list
