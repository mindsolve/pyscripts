#!/usr/bin/env python3

import click
import ldap
import sys
import pprint

# Import configuration
from config import *

# Windows doesn't understand ANSI escape sequences.
# Colorama filters them out and instead calls actual windows APIs to change colors.
if sys.platform == 'win32':
    from colorama import init as colorama_init
    colorama_init()

color = {
    'PURPLE': '\033[95m',
    'CYAN': '\033[96m',
    'DARKCYAN': '\033[36m',
    'BLUE': '\033[94m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'RED': '\033[91m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m',
    'END': '\033[0m'
}


searchAttribute = ["cn", "gweReportingTo"]
searchScope = ldap.SCOPE_SUBTREE
l = ldap.initialize(ldap_url, bytes_mode=False)

def bind_ldap(username, password):
    # Bind to the server
    try:
        l.protocol_version = ldap.VERSION3 # TODO
        l.simple_bind_s("CN={},".format(username) + user_basedn, password)
    except ldap.INVALID_CREDENTIALS:
        print("Your username or password is incorrect.")
        sys.exit(0)
    except ldap.LDAPError as e:
        if type(e.message) == dict and e.message.has_key('desc'):
            print(e.message['desc'])
        else:
            print(e)
        sys.exit(0)


def outp(res):
    if (type(res) == list):
        for item in res:
            print("Device: {}\tOwner: {}".format(item['asset_id'], item['owner']))
    else:
        print("Device: {}\tOwner: {}".format(res['asset_id'], res['owner']))


@click.command()
@click.option('--username', prompt='Your Windows logon username please', help='Windows username')
@click.option('--password', prompt='Your Windows logon password', hide_input=True, help='Windows password')
@click.option('--type', 'searchtype', default='device', show_default=True, type=click.Choice(['device', 'owner']),
    help='Whether to search by device name/inventory number or owner e-mail')
@click.argument('search', nargs=-1, type=str)
def search(username, password, searchtype, search):
    bind_ldap(username, password)

    if (searchtype == 'device'):
        for id in search:
            if id != '':
                outp(laptop_by_inv_nr(id))
    elif (searchtype == 'owner'):
        for owner in search:
            if (owner != ''):
                outp(laptop_by_owner(owner))
    else:
        print('Wrong type')
        sys.exit(1)


def laptop_by_inv_nr(inventory_number):
    searchFilter = "(sAMAccountName={}*)".format(inventory_number)
    try:
        ldap_result = l.search_s(
            basedn, searchScope, searchFilter, searchAttribute)
        res = ldap_result[0][1]
        cn = res['cn'][0].decode("utf-8")
        is_assigned = 'gweReportingTo' in res
        owner = res['gweReportingTo'][0].decode("utf-8")

        return {'asset_id': cn, 'is_assigned': is_assigned, 'owner': owner}
    except ldap.LDAPError as e:
        print(e)


def laptop_by_owner(owner):
    searchFilter = "(gweReportingTo={})".format(owner)
    # print("DEBUG: searchFilter: {}".format(searchFilter))
    try:
        ldap_result = l.search_s(
            basedn, searchScope, searchFilter, searchAttribute)
        
        return_results = []
        # print(ldap_result)
        if (len(ldap_result) > 0):
            for result in ldap_result:
                obj = result[1]
                cn = obj['cn'][0].decode("utf-8")
                is_assigned = 'gweReportingTo' in obj
                owner = obj['gweReportingTo'][0].decode("utf-8")

                return_results.append({'asset_id': cn, 'is_assigned': is_assigned, 'owner': owner})
        # else:
        #     res = ldap_result[0][1]
        #     cn = res['cn'][0].decode("utf-8")
        #     is_assigned = 'gweReportingTo' in res
        #     owner = res['gweReportingTo'][0].decode("utf-8")

        return return_results

    except ldap.LDAPError as e:
        print(e)


def searchDirect(searchtype, search, username, password):
    bind_ldap(username, password)

    if (searchtype == 'device'):
        if search != '':
            return laptop_by_inv_nr(search)
            # outp(laptop_by_inv_nr(id))
    elif (searchtype == 'owner'):
        if (search != ''):
            return laptop_by_owner(search)
            # outp(laptop_by_owner(owner))
    else:
        print('Wrong type')
        sys.exit(1)

if __name__ == '__main__':
    print('==== MAGIC USER/DEVICE SEARCH SCRIPT ====\n')
    search()