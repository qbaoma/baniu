=========
baniu
=========

Third-party SDK of `Qiniu CDN <http://developer.qiniu.com/>`_ , aimed at
creating a storage module for Django and `SAE <http://sae.sina.com.cn/>`_.

Quick start
------------

1.\ :strike:`Install this package use pip::

    pip install baniu

Or`\  install from source::

    python setup.py install

2.In your `settings.py` of your Django project deployed on the SAE sever, add the following settings::

    DEFAULT_FILE_STORAGE = 'baniu.django.storage.Storage'
    STORAGE_BUCKET_NAME = "your_qiniu_bucket_name"
    STORAGE_ACCESSKEY = "your_qiniu_api_key"
    STORAGE_SECRETKEY = "your_qiniu_api_secret"
    STORAGE_DOMAIN = "http://yourdomian_of_the_bucket"

Remeber to change `STORAGE_BUCKET_NAME`, `STORAGE_ACCESSKEY`,
`STORAGE_SECRETKEY` and `STORAGE_DOMAIN` to yours.

3.Use this module as `Django Storage <https://docs.djangoproject.com/en/1.5/ref/files/storage/>`_ .

4.Note this storage backend does not have a `location` method.

Tests
------

Use `python setup.py test` to run test.

Require `pytest`, `flake8` and `coverage`.

Documention
-------------

Install this package first.

Use `python setup.py doc` to generate `.rst` files from source.

Use `cd doc & make html` to build html docs. Open `index.html` in `doc/_build/html`.
