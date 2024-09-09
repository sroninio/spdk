#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2023 NVIDIA CORPORATION & AFFILIATES.
#  All rights reserved.

import json


def fsdev_get_opts(client):
    """Get fsdev subsystem opts.

    Args:
        NONE
    """
    return client.call('fsdev_get_opts')


def fsdev_set_opts(client, fsdev_io_pool_size: int = None, fsdev_io_cache_size: int = None):
    """Set fsdev subsystem opts.

    Args:
        fsdev_io_pool_size: size of fsdev IO objects pool
        fsdev_io_cache_size: size of fsdev IO objects cache per thread
    """
    params = {
    }

    if fsdev_io_pool_size is not None:
        params['fsdev_io_pool_size'] = fsdev_io_pool_size
    if fsdev_io_cache_size is not None:
        params['fsdev_io_cache_size'] = fsdev_io_cache_size

    return client.call('fsdev_set_opts', params)


def fsdev_get_fsdevs(client, name: str = None):
    """Get the list of fsdevs or a specific fsdev.

    Args:
        name: name of a specific fsdev
    """
    params = {
    }

    if name is not None:
        params['name'] = name

    return client.call('fsdev_get_fsdevs', params)


def fsdev_aio_create(client, name, root_path, enable_xattr: bool = None,
                     enable_writeback_cache: bool = None, max_xfer_size: int = None,
                     enable_skip_rw: bool = None, max_readahead: int = None):
    """Create a aio filesystem.

    Args:
        name: aio filesystem name
        root_path: path on system fs to expose as SPDK fs
        xattr_enabled: true if extended attributes should be enabled
        writeback_cache: enable/disable the write cache
        max_xfer_size: max data transfer size in bytes
        skip_rw: if true skips read/write IOs
        max_readahead: max readahead size
    """
    params = {
        'name': name,
        'root_path': root_path
    }
    if enable_xattr is not None:
        params['enable_xattr'] = enable_xattr
    if enable_writeback_cache is not None:
        params['enable_writeback_cache'] = enable_writeback_cache
    if max_xfer_size is not None:
        params['max_xfer_size'] = max_xfer_size
    if enable_skip_rw is not None:
        params['enable_skip_rw'] = enable_skip_rw
    if max_readahead is not None:
        params['max_readahead'] = max_readahead
    return client.call('fsdev_aio_create', params)


def fsdev_aio_delete(client, name):
    """Delete a aio filesystem.

    Args:
        name: aio filesystem name
    """
    params = {
        'name': name
    }
    return client.call('fsdev_aio_delete', params)
