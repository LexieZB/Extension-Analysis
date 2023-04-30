import os
import zipfile
import re
import json
from pathlib import Path
import traceback
import logging
import shutil
import socket
import intel

# lab_path = 'D:/ProgramD/MyCode/CS5331 Project/attemp1/lab'
# reports_path = 'D:/ProgramD/MyCode/CS5331 Project/attemp1/reports'
report = {} #'{"name":"","version":"","author":"","permissions":[{"name":"","description":"","warning":""}],"urls":"","files":{"html":"","js":"","css":"","static":"","other":""},"content-scripts":[],"background-scripts":[],"pageaction-popup":[],"browseraction-popup":[]}'
ignore_css = True
extract_email_addresses = True
extract_btc_addresses = True
extract_ipv4_addresses = True
extract_ipv6_addresses = True
extract_base64_strings = True
extract_comments = True

# ext_name = D:/ProgramD/MyCode/CS5331 Project/attemp1/extract/temp_extract_directory
# manifest_content = json.loads(manifest_content)
# rinit = core.initreport(manifest_content, extract_dir, ext_type)
def initreport(manifestjson,ext_dir,ext_type='local'):
    global report
    try:
        ext_manifest = os.path.join(ext_dir,'manifest.json')
        report['name'] = manifestjson['name']
        report['source']=''
        report['extracted']=''
        report['type']=ext_type
        report['manifest']=manifestjson
        report['version']=manifestjson['version']
        report['permissions']=[]
        report['urls'] = []
        report['emails'] = []
        report['bitcoin_addresses'] = []
        report['ipv4_addresses'] = []
        report['ipv6_addresses'] = []
        report['base64_strings'] = []
        report['comments'] = []
        report['domains'] = []
        report['files'] = {'html':[], 'json':[], 'js':[], 'css':[], 'static':[], 'other':[]}
        try:
            report['author'] = manifestjson['author']
        except:
            report['author']='unknown'
        try:
            report['description'] = manifestjson['description']
        except:
            report['description'] = 'unknown'
            print('No author name found')
        return True
    except Exception as e:
        return False


def insertpermission(permarray):
    if all(val in permarray for val in ['name', 'description', 'warning', 'badge', 'risk']):
        global report
        report['permissions'].append(permarray)
    else:
        print('Skipped adding permission "MISSING KEY". Perm: ' + str(permarray))


# analysis_status = analysis.analyze(extract_directory,'Local Firefox Extension')
# extract_directory = D:\ProgramD\MyCode\CS5331 Project\attemp1\extract\temp_extract_directory
def analyze(ext_name, ext_type='local'):
    # ext_name = D:\ProgramD\MyCode\CS5331 Project\attemp1\extract\temp_extract_directory
    # extract_dir = D:\ProgramD\MyCode\CS5331 Project\attemp1\extract\temp_extract_directory
    if os.path.isdir(ext_name):
        # if ext_name is a directory most likely it's a local extension
        ext_path = 'Local'
        extract_dir = ext_name

    else:
        return('error: [analyze.py] Unsupported input!')


    print('======== Analysis Begins ========')

    try:
        # core.updatelog('Reading manifest.json')
        print('Reading manifest.json')
        # manifest_file = helper.fixpath(extract_dir + '/manifest.json')
        manifest_file = extract_dir + '/manifest.json'
        manifest_load = open(manifest_file, 'r')
        manifest_content = manifest_load.read()
        manifest_content = json.loads(manifest_content)
        rinit = initreport(manifest_content, extract_dir, ext_type)

        if not rinit:
            return('error: Something went wrong while parsing manifest.json... analysis stopped')
        report['source'] = ext_path
        report['extracted'] = extract_dir
        # print(report)

        # # permission checks and other stuffs related to permissions
        perm_file = 'D:/ProgramD/MyCode/CS5331 Project/attemp1/db/permissions.json'
        perms = open(perm_file,'r')
        perms = perms.read()
        perms = json.loads(perms)
        try:
            for permission in manifest_content['permissions']:
                if permission !="":
                    permarray = {'name':permission}
                    if permission in perms:
                        permarray['description'] = perms[permission]['description']
                        permarray['badge'] = perms[permission]['badge']
                        permarray['risk'] = perms[permission]['risk']
                        if perms[permission]['warning'] != 'none':
                            permarray['warning'] = perms[permission]['warning']
                        else:
                            permarray['warning'] = 'na'
                    else:
                        permarray['description'] = 'na'
                        permarray['warning'] = 'na'
                        permarray['risk'] = 'none'
                        permarray['badge'] = '<i class="fas fa-question"></i>'
                    insertpermission(permarray)
                    # print(report)
        except Exception as e:
            print('No permissions found')
            # print(str(e))
        
        # Get all files and store them for further analysis
        html_files = []
        js_files = []
        json_files = []
        css_files = []
        static_files = []
        other_files = []

        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                filepath = os.path.join(root,file)
                relpath = os.path.relpath(filepath, extract_dir)
                fname = file
                file = file.lower()
                if file.endswith(('.html', '.htm')):
                    html_files.append(filepath)
                    report['files']['html'].append({fname : relpath})
                elif file.endswith('.js'):
                    js_files.append(filepath)
                    report['files']['js'].append({fname : relpath})
                elif file.endswith('.json'):
                    json_files.append(filepath)
                    report['files']['json'].append({fname : relpath})
                elif file.endswith('.css'):
                    css_files.append(filepath)
                    report['files']['css'].append({fname : relpath})
                elif file.endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.svg', '.gif')):
                    report['files']['static'].append({fname : relpath})
                    static_files.append(filepath)
                else:
                    report['files']['other'].append({fname : relpath})
                    other_files.append(filepath)
        # print(html_files)
        # print(js_files)
        # ['D:/ProgramD/MyCode/CS5331 Project/attemp1/extract/temp_extract_directory\\background.js']
        # print(json_files)
        # ['D:/ProgramD/MyCode/CS5331 Project/attemp1/extract/temp_extract_directory\\manifest.json']

        # Extract intels from files (url, email, ip address,btc address)
        urls = []
        domains = []
        # 
        for allfiles in (js_files, html_files, json_files, css_files):
            for file in allfiles:
                # print('file:',file)
                cnt = open(file, 'r', encoding="utf8")
                contents = cnt.read()
                relpath = os.path.relpath(file, extract_dir)
                # relpath: manifest.json, background.js
                try:
                    cnt = open(file, 'r', encoding="utf8")
                    contents = cnt.read()
                    relpath = os.path.relpath(file, extract_dir)
                    intels = intel.extract(contents, relpath)

                    ## Parse the intels and add them to result
                    found_urls = intels['urls']
                    found_mail = intels['mails']
                    found_btcs = intels['btc']
                    found_ipv4 = intels['ipv4']
                    found_ipv6 = intels['ipv6']
                    found_b64s = intels['base64']
                    found_cmnt = intels['comments']

                    for u in found_urls:
                        urls.append(u)
                    for m in found_mail:
                        report['emails'].append(m)
                    for b in found_btcs:
                        report['bitcoin_addresses'].append(b)
                    for i in found_ipv4:
                        report['ipv4_addresses'].append(i)
                    for i in found_ipv6:
                        report['ipv6_addresses'].append(i)
                    for b in found_b64s:
                        report['base64_strings'].append(b)
                    for c in found_cmnt:
                        report['comments'].append(c)
                except Exception as e:
                    print('Skipped reading file: {0} -- Error: {1}'.format(file, str(e)))

        # append URLS, domains to report and do virustotal scan on domains
        for url in urls:
            domain = re.findall('^(?:https?:\/\/)?(?:[^@\/\\n]+@)?(?:www\.)?([^:\/?\\n]+)', url['url'])[0]
            url['domain'] = domain
            report['urls'].append(url) # add url to the report file
            report['domains'].append(domain)
        
        # print('report:',report)
        return report





    except Exception as e:
        print('Something went wrong while reading source of manifest.json file')
        # print(e)
        # print(logging.error(traceback.format_exc()))       

"""
def handle_delete(func, path, exc_info):
    os.chmod(path, stat.S_IWRITE)
    os.unlink(path)
"""