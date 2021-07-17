from scapy.all import *
from scapy.layers import http
from colorama import Fore, Back, Style
import requests
import bs4
import warnings
import os
warnings.filterwarnings("ignore")
print(Fore.CYAN+"[+] Analyzing PCAP...")
print("")
path=sys.argv[1]
packets = rdpcap(path) #PCAP location
request_urls=[]
url_iocs=[]
ip_iocs=[]
compromised=[]
others = []
req_strs = []
httpsips = []
#----URL Mining-----
def extract_urls():
    global report
    print(Fore.CYAN+"[+] Extracting URLs to which HTTP requests were made and checking reputation...")
    print(Style.RESET_ALL)
    report=report+"<h2 style=\"text-align:center\">Possibly Malicious URLs:</h2>\n"
    for packet in packets:
        if packet.haslayer("HTTPRequest"):
            url=packet.getlayer('HTTPRequest').fields['Host']
            if url in request_urls:
                continue
            else:
                if url.find("www")!=-1:
                    request_urls.append(url.replace("www.",""))
                    url_check_rep(url.replace("www.",""))
                else:    
                    request_urls.append(url)  
                    url_check_rep(url)
        if packet.haslayer('TCP') and packet[TCP].dport == 443:
            ip=packet[IP].dst
            if not(ip in httpsips):
                httpsips.append(ip)             
    if len(url_iocs) == 0:
        report=report+"<p style=\"text-align:center ;color: red\">No Suspicious URLs found</p>"       
    if len(httpsips) == 0:
        report=report+"<p style=\"text-align:center ;color: red\">No HTTPS Traffic found</p>"          
    print("")
#----Reputation Check-----                  
def url_check_rep(url):    
    global report             
    scan_url="https://www.urlvoid.com/scan/"+url+"/"
    result=requests.get(scan_url) 
    soup = bs4.BeautifulSoup(result.content)
    blacklist_status=soup.find("span",class_="label label-danger")
    if blacklist_status != None:
        foundby=blacklist_status.text[:blacklist_status.text.find("/")]
        print(Fore.RED+url+" : Possibly Malicious")
        report=report+"<p style=\"text-align:center ;color: red\"><b>"+url+"</b> - <a target=\"_blank\" href=\""+"https://www.virustotal.com/gui/domain/"+url+"/detection"+"\">Report</a></p>\n"
        url_iocs.append(url) 
    elif soup.find("div",class_="page-header")!=None and soup.find("div",class_="page-header").find("h1").text == "Report Not Found":
        print(Fore.BLUE+url+" : Unknown")
        others.append(url)
    else:
        print(Fore.GREEN+url+" : Safe")     
def get_malicious_reqs(url):
    global report
    for packet in packets:
        if packet.haslayer("HTTPRequest"):
            if packet.getlayer('HTTPRequest').fields['Host'] == url:
                ip=packet.getlayer('IP').fields
                ether=packet.getlayer('Ether').fields
                req=packet.getlayer('HTTPRequest').fields
                req_str=str(ip['src'])+" made a "+str(req["Method"])+" request to "+str(req["Host"])+str(req["Path"])+" ["+str(ip['dst'])+"]"
                if req_str in req_strs:
                    continue
                else:
                    req_strs.append(req_str)
                    report=report+"<p style=\"text-align:center ;color: red\"><b>"+req_str+"</b></p>\n"
                if not(ip['dst'] in ip_iocs):
                    ip_iocs.append(ip['dst'])
                if not(ip['src'] in compromised):
                    compromised.append(ip['src']) 
                    compromised.append(ether['src'])  
#---Function Calls---           
report="<h1 style=\"text-align:center\"><u>Possible IoCs</u></h1>\n"
extract_urls()
print("")
report=report+"<h2 style=\"text-align:center\">Unknown IPs/Domains to be checked:</h2>\n"
for ioc in others:
    report=report+"<p style=\"text-align:center ;color: red\"><b>"+ioc+"</b> : - <a target=\"_blank\" href=\""+"https://www.virustotal.com/gui/search/"+ioc+"\">Report</a></p>\n"
report=report+"<h2 style=\"text-align:center\">HTTPS Traffic to be checked:</h2>\n"
report=report+"<p style=\"text-align:center;color: red\"><b>List of destination IPs to which HTTPS requests were made - </b><a target=\"_blank\" href=\"httpsips.txt\">List</a></p>"
report=report+"<h2 style=\"text-align:center\">All Unknown/Malicious Requests to be checked:</h2>\n"
print(Fore.CYAN+"[+] Extracting possibly malicious requests made...") 
print("")
for url in url_iocs:
    get_malicious_reqs(url)
for url in others:
    get_malicious_reqs(url)
print("")    
report="<h4>"+"Possibly compromised Hosts: "+str(compromised)+"</h4>"+report
os.system("mkdir Report-"+path)
os.system("cd Report-"+path)
file = open("Report-"+path+"/report.html","w")
file.write(report)
file.close()
file = open("Report-"+path+"/httpsips.txt","w")
for ip in httpsips:
    file.write(ip+"\n")
file.close()
print("Report Generated!")
print("")
