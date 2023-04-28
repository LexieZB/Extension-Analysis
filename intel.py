import re
import analyze

def escape(html):
    return(html.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;'))

def extract(contents, relpath):
    # extract the following:
    # URL, Email, BTC Address, IPV4 IPV6 Addresses, Base64 Encoded strings
    # content = file content
    # relpath = relative path (for json entry in result)

    found_urls = [] # URLS -> (http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?
    found_mail = [] # emails -> ([a-zA-Z0-9\.\-_]+(?:@| ?\[(?:at)\] ?)[a-zA-Z0-9\.\-]+(?:\.| ?\[(?:dot)\] ?)[a-zA-Z]+)
    found_btcs = [] # bitcoin address -> [^a-zA-Z0-9]([13][a-km-zA-HJ-NP-Z1-9]{26,33})[^a-zA-Z0-9]
    found_ipv4 = [] # IPv4 addr -> [^a-zA-Z0-9]([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[^a-zA-Z0-9]
    found_ipv6 = [] # IPV6 -> (([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?=\s|$)
    found_b64s = [] # base64 -> (?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)
    found_cmnt = [] # Comments -> ...

    if analyze.ignore_css and relpath.endswith('.css'):
        print('ignore css')
        result = {
            "urls":found_urls, 
            "mails":found_mail, 
            "ipv4":found_ipv4, 
            "ipv6":found_ipv6, 
            "base64":found_b64s, 
            "btc":found_btcs,
            "comments":found_cmnt
        }
        return result
    
    # extract URLs from js, html, css and json files
    curls = re.findall('(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?', contents)
    for url in curls:
        urlresult = {"file":relpath, "url":url[0]+'://'+url[1]+url[2]}
        if urlresult not in found_urls:
            found_urls.append(urlresult)
    
    # extract email IDs from js, html, json and css files
    if analyze.extract_email_addresses:
        cmails = re.findall('([a-zA-Z0-9\.\-_]+(?:@| ?\[(?:at)\] ?)[a-zA-Z0-9\.\-]+(?:\.| ?\[(?:dot)\] ?)[a-zA-Z]+)', contents)
        for mail in cmails:
            mail = mail.replace('[at]', '@').replace('[dot]','.')
            mailarray = {"mail":mail, "file":relpath}
            if mailarray not in found_mail:
                found_mail.append(mailarray)
    
    # extract bitcoin addresses
    if analyze.extract_btc_addresses:
        btc_addresses = re.findall('[^a-zA-Z0-9]([13][a-km-zA-HJ-NP-Z1-9]{26,33})[^a-zA-Z0-9]', contents)
        for btc_address in btc_addresses:
            btcarr = {"address":btc_address, "file":relpath}
            if btcarr not in found_btcs:
                found_btcs.append(btcarr)

    # extract IPV6 addresses
    if analyze.extract_ipv6_addresses:
        ipv6s = re.findall('(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?=\s|$)', contents)
        for ipv6 in ipv6s:
            addr = ipv6[0]
            v6arr = {"address":addr, "file":relpath}
            if v6arr not in found_ipv6:
                found_ipv6.append(v6arr)

    # extract IPV4 addresses
    if analyze.extract_ipv4_addresses:
        ipv4s = re.findall('[^a-zA-Z0-9]([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[^a-zA-Z0-9]', contents)
        for ipv4 in ipv4s:
            iparr = {"address":ipv4, "file":relpath}
            if iparr not in found_ipv4:
                found_ipv4.append(iparr)

    if analyze.extract_base64_strings:
        base64_strings = re.findall('(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)', contents)
        for base64_string in base64_strings:
            stringarr = {"string":base64_string, "file":relpath}
            if stringarr not in found_b64s:
                found_b64s.append(stringarr)

    # extract comments from JS and HTML files
    if analyze.extract_comments:
        if relpath.endswith(('.html', '.js', '.htm', '.css')):
            c1 = re.findall('\/\*.*?\*\/|\/\/(.*?)\n|\$', contents)
            c2 = re.findall('\/\* *([^\"\']+?) *\*\/', contents)
            c3 = re.findall('<!-- *(.+?) *-->', contents)
            c1.extend(c2)
            c1.extend(c3)
            comments = c1
            for comment in comments:
                if comment != "" and comment != " ":
                    comment = escape(comment) # escape html
                    cmarray = {"comment":comment, "file":relpath}
                    if cmarray not in found_cmnt:
                        found_cmnt.append(cmarray)

    result = {
                "urls":found_urls, 
                "mails":found_mail, 
                "ipv4":found_ipv4, 
                "ipv6":found_ipv6, 
                "base64":found_b64s, 
                "btc":found_btcs,
                "comments":found_cmnt
            }
    return result



