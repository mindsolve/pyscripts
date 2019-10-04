#!/usr/bin/env python3
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)
import sys
import json
import urllib.parse
from datetime import datetime
import re
import terminaltables

# LDAP search
import user_inv

# Configuration
from config import *

# Debug/development
from colorama import Fore, Back, Style, init as colorama_init
# Convert ANSI escape sequences to win32 api calls (only on windows)
colorama_init()
import pprint

## Set default timeout
class MyHTTPAdapter(requests.adapters.HTTPAdapter):
    def send(self, *args, **kwargs):
        kwargs['timeout'] = 25
        return super(MyHTTPAdapter, self).send(*args, **kwargs)

adapter = MyHTTPAdapter(max_retries=1)

session = requests.Session()
session.mount('https://', adapter)
session.mount('http://', adapter)

cookies = {
    'JSESSIONID': None
}

session.proxies.update(proxy_dict)
session.verify = False

def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f %s%s" % (num, 'Yi', suffix)

def login():
    print(Fore.LIGHTBLACK_EX + 'Logging in...' + Fore.RESET)
    login_url = baseurl + "/webacs/j_spring_security_check"
    login_params = {
        'j_username': newton_username,
        'j_password': newton_password,
        'action': 'login'
    }
    
    try:
        login_req = session.post(login_url, login_params)
    except requests.exceptions.ReadTimeout:
        print(Fore.RED + 'Login unsuccessful: Timeout while waiting for response' + Fore.RESET)
        return False

    if (login_req.status_code == 302) or (login_req.status_code == 200):
        print(Fore.LIGHTBLACK_EX + 'Login successful.' + Fore.RESET + '\n')
        return True
    else:
        print(Fore.RED + 'Login unsuccessful: HTTP code {}', login_req.status_code + Fore.RESET)
        return False


def logout():
    logout_url = baseurl + "/webacs/j_spring_security_logout"
    logout_req = session.get(logout_url, allow_redirects=True)

    logout_success = True
    logout_error_msg = ""

    if len(logout_req.history) != 2:
        logout_success = False
        logout_error_msg = "Wrong redirect count"
    
    if logout_req.url != baseurl + "/webacs/pages/common/login.jsp":
        logout_success = False
        logout_error_msg = "Did not redirect to login page"
    
    if logout_req.history[0].url != baseurl + "/webacs/j_spring_security_logout":
        logout_success = False
        logout_error_msg = "Did not redirect from logout page"

    if logout_req.history[1].url != baseurl + "/webacs/j_spring_cas_security_logout":
        logout_success = False
        logout_error_msg = "Did not redirect via cas_security_logout page"

    
    if logout_success != True:
        print(Fore.RED + 'Error while logging out: {}'.format(logout_error_msg) + Fore.RESET)
        print('Current state:')
        print('URL: {}'.format(logout_req.url))
        print('HTTP status code: {}'.format(logout_req.status_code))
    else:
        print(Fore.LIGHTBLACK_EX + 'Logout successful' + Fore.RESET)


def request_client_topology(mac_addr):
    topology_url = baseurl + "/webacs/rs/rfm/clientservice/getClientTopology?macAddress={}".format(mac_addr)
    topology_req = session.get(topology_url)
    try:
        topology_temp_obj = json.loads(topology_req.text)
    except Exception as e:
        print(Fore.RED + 'Error:', e, Fore.RESET)
        exit(1)

    topology_list = parse_client_topology(topology_temp_obj)
    topology_list.reverse()
    return topology_list


def parse_client_topology(topo_obj):
    our_list = []
    if 'children' in topo_obj:
        our_list = parse_client_topology(topo_obj["children"][0])
    
    our_list += [{'name': topo_obj['name'], 'type': topo_obj['iconType']}]
    return our_list


def request_device_details(mac_addr):
    details_url = baseurl + "/webacs/rs/rfm/clientservice/getClientDetail?macAddress={}&deviceIpAddress=".format(mac_addr)
    device_detail_req = session.get(details_url, allow_redirects=False)
    device_detail_obj = json.loads(device_detail_req.text)

    ap_details = {
        'heirarchyName': None,
        'lradName': None,
        'accessPointTypeString': None
    }
    client_details = {
        'bytesReceived': None,
        'bytesSent': None,
        'ipAddress': None, # Client IP
        'eventTime': None, # Last connect/disconnect event
        'protocolString': None, # '802.11n(2.4GHz)' or '802.11n(5GHz)'
        'rssi': None,
        'rxBytesDropped': None,
        'txBytesDropped': None,
        'rxPacketsDropped': None,
        'txPacketsDropped': None,
        'ssId': None,
        'throughput': None,
        'statusString': None, # Association status
        'sessionTime': None # Time of last session, from last assoc to disassoc (or now, if still assoc) [in ms]
    }

    for detail_dict in ap_details, client_details:
        for detail in detail_dict:
            if detail in device_detail_obj:
                detail_dict[detail] = device_detail_obj[detail]

    return (ap_details, client_details)


def request_search_device(search_str):
    search_str = urllib.parse.quote(search_str, safe='')
    search_url = baseurl + "/webacs/api/v1/op/search/quick.json?query={}&.transform=mappedFieldsTransformer".format(search_str)
    search_result_req = session.get(search_url, allow_redirects=False)
    
    if search_result_req.headers.get('Location') != None:
        if login():
            search_result_req = session.get(search_url, allow_redirects=False)
        else:
            print(Fore.RED + "Error while logging in. Exiting." + Fore.RESET)
            return
    
    try:
        search_result_obj = json.loads(search_result_req.text)
    except Exception as e:
        print(Fore.RED + 'Error:', e, Fore.RESET)
        exit(1)

    results = []

    if ('searchLists' in search_result_obj):
        for result_entry in search_result_obj['searchLists'][0]['searchEntity']:
            results.append(result_entry)
    else:
        print(Fore.YELLOW + 'WARN: No devices found. Check spelling.' + Fore.RESET)

    return results

def search_device(search_str):
    def print_detail(key, value):
        if value is None or value is '':
            value = Fore.LIGHTBLACK_EX + 'N/A' + Fore.RESET
        else:
            value = Fore.BLUE + str(value) + Fore.RESET
        
        print("{}: {}".format(key, value))
    
    results = request_search_device(search_str)
    if (results != None and len(results) > 0):
        for device in results:
            userName = device['userName']
            macAddress = device['macAddress']
            ipAddress = device['ipAddress']
            clientVendor = device['clientVendor']
            ap_details, client_details = request_device_details(macAddress)

            print(Back.BLUE + "Device {}:".format(userName) + Back.RESET)
            print_detail('MAC', macAddress)
            print_detail('IP', ipAddress)
            print_detail('WLAN-Manuf.', clientVendor)
            print_detail('WLAN-Tech.', client_details['protocolString'])
            print_detail('Last RSSI', str(client_details['rssi']) + ' dBm')
            print_detail('SSID', client_details['ssId'])
            print_detail('Bytes sent', sizeof_fmt(client_details['bytesSent']))
            print_detail('Bytes received', sizeof_fmt(client_details['bytesReceived']))
            print()
            print_detail('Status', client_details['statusString'])
            eventDate = datetime.fromtimestamp(client_details['eventTime']/1000.0)
            print_detail('Since', eventDate)
            eventDateShort = eventDate.replace(microsecond=0)
            nowDate = datetime.now().replace(microsecond=0)
            print_detail('For', (nowDate-eventDateShort))
            print()
            print_detail('Current AP', ap_details['lradName'])
            print_detail('AP Type', ap_details['accessPointTypeString'])
            print_detail('Location', ap_details['heirarchyName'])
            print()

            topology = request_client_topology(macAddress)
            print(Fore.LIGHTCYAN_EX + 'Topology:' + Fore.RESET)
            for layer, topology_layer in enumerate(topology):
                pre_text = " "*(layer+2)
                if layer != 0:
                    pre_text += u'\u21B3 '
                print(pre_text + "[{}] {}".format(topology_layer['type'], topology_layer['name']))
            print()

            print_device_history(macAddress)

            
    else:
        print(Fore.RED + 'No matches found.' + Fore.RESET)
        return
    print()


def request_device_history(mac_addr, timeframe='4w', max_items=100):
    assoc_history_baseurl = baseurl + "/webacs/monitorClientDetail.do?command=associationHistory&clientType=0&action=login&product=wcs&selectedCategory=en&json=true&pager.offset=0&isAscending=false&orderByColumn=eventTimeStampWithMilliSec&sort=-eventTimeStampWithMilliSec"
    assoc_history_timeframe = "&duration={}".format(str(timeframe))
    assoc_history_maxitems = "&itemsPerPage={}".format(str(max_items))
    assoc_history_mac = "&mobileStationMac={}".format(str(mac_addr))
    assoc_history_url = assoc_history_baseurl + assoc_history_timeframe + assoc_history_maxitems + assoc_history_mac

    assoc_history_req = session.get(assoc_history_url, allow_redirects=False)
    assoc_history_obj = json.loads(assoc_history_req.text)

    history = []

    if 'numRows' in assoc_history_obj and int(assoc_history_obj['numRows']) > 0:
        numRows = int(assoc_history_obj['numRows'])
        for orig_hist_item in assoc_history_obj['items']:
            hist_item = {
                'apName': None,
                'bytesReceived': None,
                'bytesSent': None,
                # 'packetsReceived': None,
                # 'packetsSent': None,
                # 'clientIpAddress': None,
                'location': None,
                # 'protocolString': None, # Type of connection (e.g. 802.11n(5GHz))
                'sessionStartTime': None, # millis() timestamp
                'sessionEndTime': None, # millis() timestamp
                'sessionTime': None, # Duration of session, in ms
                'statusString': None, # Current status
                'traffic': None, # Total traffic (MB)
            }

            for key in hist_item:
                if key in orig_hist_item:
                    hist_item[key] = orig_hist_item[key]
                else:
                    hist_item[key] = None

            history.append(hist_item)
    else:
        numRows = 0
    
    return (numRows, history)


def print_device_history(mac_addr, timeframe='2w', max_items=10):
    numRows, device_history = request_device_history(mac_addr, timeframe, max_items)
    print(Fore.LIGHTBLACK_EX + 'Displaying last {} of {} sessions for timeframe {}'.format(len(device_history), numRows, timeframe) + Fore.RESET)
    if len(device_history) > 0:
        from terminaltables import SingleTable
        values = []
        
        for counter, hist_item in enumerate(device_history):
            table_row = {
                'Session\n(Start)': datetime.fromtimestamp(int(hist_item['sessionStartTime'])/1000.0).replace(microsecond=0),
                'Session\n(End)': datetime.fromtimestamp(int(hist_item['sessionEndTime'])/1000.0).replace(microsecond=0),
                'Session\n(Duration)': datetime.fromtimestamp(int(hist_item['sessionTime'])/1000.0).replace(microsecond=0)-datetime.fromtimestamp(0),
                'AP Name': hist_item['apName'],
                'Location': hist_item['location'],
                'Traffic\n(Received)': sizeof_fmt(int(hist_item['bytesReceived'])),
                'Traffic\n(Sent)': sizeof_fmt(int(hist_item['bytesSent'])),
                'Traffic\n(Total)': hist_item['traffic'] + ' MiB', # Total traffic (MiB)
                # Duration of session
                'Current Status': hist_item['statusString'], # Current status
            }

            if int(hist_item['sessionEndTime']) == 4102444800000:
                table_row['Session\n(End)'] = Fore.LIGHTGREEN_EX + '(still active)' + Fore.RESET

            if counter == 0:
                values = [list(table_row.keys())]

            values.append(list(table_row.values()))

        table = SingleTable(values, Fore.LIGHTCYAN_EX + 'Device Association History' + Fore.RESET)
        print(table.table)
    else:
        print('No history available within the specified timeframe.')
        


def search_asset_by_owner(search_string):
    import getpass
    print('Searching for \"{}\" in LDAP...'.format(search_string))
    ldap_username = input("Your Windows username: ")
    ldap_password = getpass.getpass("Your Windows password: ")
    result = user_inv.searchDirect('owner', search_string, ldap_username, ldap_password)

    device_ids = []
    for found_device in result:
        device_ids.append(found_device['asset_id'])
    
    print(Fore.LIGHTBLACK_EX + 'Found {} assets matching your request.'.format(len(device_ids)) + Fore.RESET)
    return device_ids

# Only run this if interactive, not if imported
if __name__=="__main__":
    if (len(sys.argv) > 1):
        arg = sys.argv[1]
        if re.match(r"^E[0-9]{7}$", arg):
            print("You entered an asset-id.")
            identifiers = [arg]
        elif re.match(r"^(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})$", arg):
            print("You entered a MAC-address.")
            identifiers = [arg]
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", arg):
            print("You entered an IP-address.")
            identifiers = [arg]
        else:
            print("You did not enter an asset-id. Assuming LDAP owner search string.")
            identifiers = search_asset_by_owner(arg)

        for identifier in identifiers:
            search_device(identifier)
        
        logout()
    else:
        print('Usage:\n{0} <Inventory-ID>|<IP>|<MAC-Addr>\n{0} <Owner LDAP search string>'.format(__file__))
