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





def fsdev_nfs_create(client, name):
    """Create an nfs filesystem.

    Args:
        name: nfs filesystem name
    """
    # print("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB fsdev_nfs_create (fdsev.py)")
    params = {
        'name': name,
    }
    return client.call('fsdev_nfs_create', params)





def fsdev_nfs_delete(client, name):
    """Delete an nfs filesystem.

    Args:
        name: nfs filesystem name
    """
    params = {
        'name': name
    }
    return client.call('fsdev_nfs_delete', params)
