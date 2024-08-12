#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2018 Intel Corporation.
#  All rights reserved.


def framework_get_subsystems(client):
    return client.call('framework_get_subsystems')


def framework_disable_subsystem(client, name):
    params = {'name': name}
    return client.call('framework_disable_subsystem', params)


def framework_enable_subsystem(client, name):
    params = {'name': name}
    return client.call('framework_enable_subsystem', params)


def framework_get_config(client, name):
    params = {'name': name}
    return client.call('framework_get_config', params)


def framework_get_pci_devices(client):
    return client.call('framework_get_pci_devices')
