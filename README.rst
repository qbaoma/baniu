===========================
baniu
===========================

Third party SDK of `Qiniu CDN <http://developer.qiniu.com/>`_ , aimed to create
a storage module for Django and `SAE <http://sae.sina.com.cn/>`_.

Quick start
------------

1.Install `baniu` with setup.py or put the `baniu` module to your PYTHONPATH.

2.In your `settings.py`, add the following settings::

    DEFAULT_FILE_STORAGE = 'baniu.django.storage.Storage'
    STORAGE_BUCKET_NAME = "your_qiniu_bucket_name"
    STORAGE_ACCESSKEY = "your_qiniu_api_key"
    STORAGE_SECRETKEY = "your_qiniu_api_secret"
    STORAGE_DOMAIN = "http://yourdomian_of_the_bucket"

Remeber to change `STORAGE_BUCKET_NAME`, `STORAGE_ACCESSKEY`,
`STORAGE_SECRETKEY` and `STORAGE_DOMAIN` to yours.

3.Use this module as `Django Storage <https://docs.djangoproject.com/en/1.5/ref/files/storage/>`_ .
