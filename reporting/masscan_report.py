# masscan_report.py
#
# This script takes a masscan list file as input and produces
# a text-based report that can be used to produce the final
# report for a segmentation test.
#
# Usage: masscan_report.py <targets file> <masscan list file>
# Optional arguments:
#   -s <service detection directory>
#   -c <csv output file>
#

import argparse
import csv
import ipaddress
import os
import random
import string
import sys
from operator import itemgetter, attrgetter


# nmap top 1000 TCP services and top 100 UDP services
SERVICE_DB = {
    'tcp/80': ' http',
    'tcp/23': ' telnet',
    'tcp/443': ' https',
    'tcp/21': ' ftp',
    'tcp/22': ' ssh',
    'tcp/25': ' smtp',
    'tcp/3389': ' ms-wbt-server',
    'tcp/110': ' pop3',
    'tcp/445': ' microsoft-ds',
    'tcp/139': ' netbios-ssn',
    'tcp/143': ' imap',
    'tcp/53': ' domain',
    'tcp/135': ' msrpc',
    'tcp/3306': ' mysql',
    'tcp/8080': ' http-proxy',
    'tcp/1723': ' pptp',
    'tcp/111': ' rpcbind',
    'tcp/995': ' pop3s',
    'tcp/993': ' imaps',
    'tcp/5900': ' vnc',
    'tcp/1025': ' NFS-or-IIS',
    'tcp/587': ' submission',
    'tcp/8888': ' sun-answerbook',
    'tcp/199': ' smux',
    'tcp/1720': ' h323q931',
    'tcp/465': ' smtps',
    'tcp/548': ' afp',
    'tcp/113': ' ident',
    'tcp/81': ' hosts2-ns',
    'tcp/6001': ' X11:1',
    'tcp/10000': ' snet-sensor-mgmt',
    'tcp/514': ' shell',
    'tcp/5060': ' sip',
    'tcp/179': ' bgp',
    'tcp/1026': ' LSA-or-nterm',
    'tcp/2000': ' cisco-sccp',
    'tcp/8443': ' https-alt',
    'tcp/8000': ' http-alt',
    'tcp/32768': ' filenet-tms',
    'tcp/554': ' rtsp',
    'tcp/26': ' rsftp',
    'tcp/1433': ' ms-sql-s',
    'tcp/49152': ' unknown',
    'tcp/2001': ' dc',
    'tcp/515': ' printer',
    'tcp/8008': ' http',
    'tcp/49154': ' unknown',
    'tcp/1027': ' IIS',
    'tcp/5666': ' nrpe',
    'tcp/646': ' ldp',
    'tcp/5000': ' upnp',
    'tcp/5631': ' pcanywheredata',
    'tcp/631': ' ipp',
    'tcp/49153': ' unknown',
    'tcp/8081': ' blackice-icecap',
    'tcp/2049': ' nfs',
    'tcp/88': ' kerberos-sec',
    'tcp/79': ' finger',
    'tcp/5800': ' vnc-http',
    'tcp/106': ' pop3pw',
    'tcp/2121': ' ccproxy-ftp',
    'tcp/1110': ' nfsd-status',
    'tcp/49155': ' unknown',
    'tcp/6000': ' X11',
    'tcp/513': ' login',
    'tcp/990': ' ftps',
    'tcp/5357': ' wsdapi',
    'tcp/427': ' svrloc',
    'tcp/49156': ' unknown',
    'tcp/543': ' klogin',
    'tcp/544': ' kshell',
    'tcp/5101': ' admdog',
    'tcp/144': ' news',
    'tcp/7': ' echo',
    'tcp/389': ' ldap',
    'tcp/8009': ' ajp13',
    'tcp/3128': ' squid-http',
    'tcp/444': ' snpp',
    'tcp/9999': ' abyss',
    'tcp/5009': ' airport-admin',
    'tcp/7070': ' realserver',
    'tcp/5190': ' aol',
    'tcp/3000': ' ppp',
    'tcp/5432': ' postgresql',
    'tcp/1900': ' upnp',
    'tcp/3986': ' mapper-ws_ethd',
    'tcp/13': ' daytime',
    'tcp/1029': ' ms-lsa',
    'tcp/9': ' discard',
    'tcp/5051': ' ida-agent',
    'tcp/6646': ' unknown',
    'tcp/49157': ' unknown',
    'tcp/1028': ' unknown',
    'tcp/873': ' rsync',
    'tcp/1755': ' wms',
    'tcp/2717': ' pn-requester',
    'tcp/4899': ' radmin',
    'tcp/9100': ' jetdirect',
    'tcp/119': ' nntp',
    'tcp/37': ' time',
    'tcp/1000': ' cadlock',
    'tcp/3001': ' nessus',
    'tcp/5001': ' commplex-link',
    'tcp/82': ' xfer',
    'tcp/10010': ' rxapi',
    'tcp/1030': ' iad1',
    'tcp/9090': ' zeus-admin',
    'tcp/2107': ' msmq-mgmt',
    'tcp/1024': ' kdm',
    'tcp/2103': ' zephyr-clt',
    'tcp/6004': ' X11:4',
    'tcp/1801': ' msmq',
    'tcp/5050': ' mmcc',
    'tcp/19': ' chargen',
    'tcp/8031': ' unknown',
    'tcp/1041': ' danf-ak2',
    'tcp/255': ' unknown',
    'tcp/1048': ' neod2',
    'tcp/1049': ' td-postman',
    'tcp/1053': ' remote-as',
    'tcp/1054': ' brvread',
    'tcp/1056': ' vfo',
    'tcp/1064': ' jstel',
    'tcp/1065': ' syscomlan',
    'tcp/2967': ' symantec-av',
    'tcp/3703': ' adobeserver-3',
    'tcp/17': ' qotd',
    'tcp/808': ' ccproxy-http',
    'tcp/3689': ' rendezvous',
    'tcp/1031': ' iad2',
    'tcp/1044': ' dcutility',
    'tcp/1071': ' bsquare-voip',
    'tcp/5901': ' vnc-1',
    'tcp/100': ' newacct',
    'tcp/9102': ' jetdirect',
    'tcp/1039': ' sbl',
    'tcp/2869': ' icslap',
    'tcp/4001': ' newoak',
    'tcp/5120': ' barracuda-bbs',
    'tcp/8010': ' xmpp',
    'tcp/9000': ' cslistener',
    'tcp/2105': ' eklogin',
    'tcp/636': ' ldapssl',
    'tcp/1038': ' mtqp',
    'tcp/2601': ' zebra',
    'tcp/1': ' tcpmux',
    'tcp/7000': ' afs3-fileserver',
    'tcp/1066': ' fpo-fns',
    'tcp/1069': ' cognex-insight',
    'tcp/625': ' apple-xsrvr-admin',
    'tcp/311': ' asip-webadmin',
    'tcp/280': ' http-mgmt',
    'tcp/254': ' unknown',
    'tcp/4000': ' remoteanything',
    'tcp/1761': ' landesk-rc',
    'tcp/5003': ' filemaker',
    'tcp/2002': ' globe',
    'tcp/1998': ' x25-svc-port',
    'tcp/2005': ' deslogin',
    'tcp/1032': ' iad3',
    'tcp/1050': ' java-or-OTGfileshare',
    'tcp/6112': ' dtspc',
    'tcp/3690': ' svn',
    'tcp/1521': ' oracle',
    'tcp/2161': ' apc-agent',
    'tcp/1080': ' socks',
    'tcp/6002': ' X11:2',
    'tcp/2401': ' cvspserver',
    'tcp/902': ' iss-realsecure',
    'tcp/4045': ' lockd',
    'tcp/787': ' qsc',
    'tcp/7937': ' nsrexecd',
    'tcp/1058': ' nim',
    'tcp/2383': ' ms-olap4',
    'tcp/32771': ' sometimes-rpc5',
    'tcp/1033': ' netinfo',
    'tcp/1040': ' netsaint',
    'tcp/1059': ' nimreg',
    'tcp/50000': ' ibm-db2',
    'tcp/5555': ' freeciv',
    'tcp/10001': ' scp-config',
    'tcp/1494': ' citrix-ica',
    'tcp/3': ' compressnet',
    'tcp/593': ' http-rpc-epmap',
    'tcp/2301': ' compaqdiag',
    'tcp/3268': ' globalcatLDAP',
    'tcp/7938': ' lgtomapper',
    'tcp/1022': ' exp2',
    'tcp/1234': ' hotline',
    'tcp/1035': ' multidropper',
    'tcp/1036': ' nsstp',
    'tcp/1037': ' ams',
    'tcp/1074': ' warmspotMgmt',
    'tcp/8002': ' teradataordbms',
    'tcp/9001': ' tor-orport',
    'tcp/464': ' kpasswd5',
    'tcp/497': ' retrospect',
    'tcp/1935': ' rtmp',
    'tcp/2003': ' finger',
    'tcp/6666': ' irc',
    'tcp/6543': ' mythtv',
    'tcp/24': ' priv-mail',
    'tcp/1352': ' lotusnotes',
    'tcp/3269': ' globalcatLDAPssl',
    'tcp/1111': ' lmsocialserver',
    'tcp/407': ' timbuktu',
    'tcp/500': ' isakmp',
    'tcp/20': ' ftp-data',
    'tcp/2006': ' invokator',
    'tcp/1034': ' zincite-a',
    'tcp/1218': ' aeroflight-ads',
    'tcp/3260': ' iscsi',
    'tcp/15000': ' hydap',
    'tcp/4444': ' krb524',
    'tcp/264': ' bgmp',
    'tcp/33': ' dsp',
    'tcp/2004': ' mailbox',
    'tcp/1042': ' afrog',
    'tcp/42510': ' caerpc',
    'tcp/999': ' garcon',
    'tcp/3052': ' powerchute',
    'tcp/1023': ' netvenuechat',
    'tcp/222': ' rsh-spx',
    'tcp/1068': ' instl_bootc',
    'tcp/888': ' accessbuilder',
    'tcp/7100': ' font-service',
    'tcp/563': ' snews',
    'tcp/1717': ' fj-hdnet',
    'tcp/992': ' telnets',
    'tcp/2008': ' conf',
    'tcp/32770': ' sometimes-rpc3',
    'tcp/7001': ' afs3-callback',
    'tcp/32772': ' sometimes-rpc7',
    'tcp/2007': ' dectalk',
    'tcp/8082': ' blackice-alerts',
    'tcp/5550': ' sdadmind',
    'tcp/512': ' exec',
    'tcp/1043': ' boinc',
    'tcp/2009': ' news',
    'tcp/5801': ' vnc-http-1',
    'tcp/1700': ' mps-raft',
    'tcp/2701': ' sms-rcinfo',
    'tcp/7019': ' doceri-ctl',
    'tcp/50001': ' unknown',
    'tcp/4662': ' edonkey',
    'tcp/2065': ' dlsrpn',
    'tcp/42': ' nameserver',
    'tcp/2010': ' search',
    'tcp/161': ' snmp',
    'tcp/2602': ' ripd',
    'tcp/3333': ' dec-notes',
    'tcp/9535': ' man',
    'tcp/5100': ' admd',
    'tcp/2604': ' ospfd',
    'tcp/4002': ' mlchat-proxy',
    'tcp/5002': ' rfe',
    'tcp/1047': ' neod1',
    'tcp/1051': ' optima-vnet',
    'tcp/1052': ' ddt',
    'tcp/1055': ' ansyslmd',
    'tcp/1060': ' polestar',
    'tcp/1062': ' veracity',
    'tcp/1311': ' rxmon',
    'tcp/2702': ' sms-xfer',
    'tcp/3283': ' netassistant',
    'tcp/4443': ' pharos',
    'tcp/5225': ' hp-server',
    'tcp/5226': ' hp-status',
    'tcp/6059': ' X11:59',
    'tcp/6789': ' ibm-db2-admin',
    'tcp/8089': ' unknown',
    'tcp/8192': ' sophos',
    'tcp/8193': ' sophos',
    'tcp/8194': ' sophos',
    'tcp/8651': ' unknown',
    'tcp/8652': ' unknown',
    'tcp/8701': ' unknown',
    'tcp/9415': ' unknown',
    'tcp/9593': ' cba8',
    'tcp/9594': ' msgsys',
    'tcp/9595': ' pds',
    'tcp/16992': ' amt-soap-http',
    'tcp/16993': ' amt-soap-https',
    'tcp/20828': ' unknown',
    'tcp/23502': ' unknown',
    'tcp/32769': ' filenet-rpc',
    'tcp/33354': ' unknown',
    'tcp/35500': ' unknown',
    'tcp/52869': ' unknown',
    'tcp/55555': ' unknown',
    'tcp/55600': ' unknown',
    'tcp/64623': ' unknown',
    'tcp/64680': ' unknown',
    'tcp/65000': ' unknown',
    'tcp/65389': ' unknown',
    'tcp/1067': ' instl_boots',
    'tcp/13782': ' netbackup',
    'tcp/366': ' odmr',
    'tcp/5902': ' vnc-2',
    'tcp/9050': ' tor-socks',
    'tcp/85': ' mit-ml-dev',
    'tcp/1002': ' windows-icfw',
    'tcp/5500': ' hotline',
    'tcp/1863': ' msnp',
    'tcp/1864': ' paradym-31',
    'tcp/5431': ' park-agent',
    'tcp/8085': ' unknown',
    'tcp/10243': ' unknown',
    'tcp/45100': ' unknown',
    'tcp/49999': ' unknown',
    'tcp/51103': ' unknown',
    'tcp/49': ' tacacs',
    'tcp/90': ' dnsix',
    'tcp/6667': ' irc',
    'tcp/1503': ' imtc-mcs',
    'tcp/6881': ' bittorrent-tracker',
    'tcp/27000': ' flexlm0',
    'tcp/340': ' unknown',
    'tcp/1500': ' vlsi-lm',
    'tcp/8021': ' ftp-proxy',
    'tcp/2222': ' EtherNetIP-1',
    'tcp/5566': ' westec-connect',
    'tcp/8088': ' radan-http',
    'tcp/8899': ' ospf-lite',
    'tcp/9071': ' unknown',
    'tcp/1501': ' sas-3',
    'tcp/5102': ' admeng',
    'tcp/6005': ' X11:5',
    'tcp/9101': ' jetdirect',
    'tcp/9876': ' sd',
    'tcp/32773': ' sometimes-rpc9',
    'tcp/32774': ' sometimes-rpc11',
    'tcp/163': ' cmip-man',
    'tcp/5679': ' activesync',
    'tcp/146': ' iso-tp0',
    'tcp/648': ' rrp',
    'tcp/1666': ' netview-aix-6',
    'tcp/901': ' samba-swat',
    'tcp/83': ' mit-ml-dev',
    'tcp/3476': ' nppmp',
    'tcp/5004': ' avt-profile-1',
    'tcp/5214': ' unknown',
    'tcp/8001': ' vcom-tunnel',
    'tcp/8083': ' us-srv',
    'tcp/8084': ' unknown',
    'tcp/9207': ' wap-vcal-s',
    'tcp/14238': ' unknown',
    'tcp/30': ' unknown',
    'tcp/912': ' apex-mesh',
    'tcp/12345': ' netbus',
    'tcp/2030': ' device2',
    'tcp/2605': ' bgpd',
    'tcp/6': ' unknown',
    'tcp/541': ' uucp-rlogin',
    'tcp/4': ' unknown',
    'tcp/1248': ' hermes',
    'tcp/3005': ' deslogin',
    'tcp/8007': ' ajp12',
    'tcp/306': ' unknown',
    'tcp/880': ' unknown',
    'tcp/2500': ' rtsserv',
    'tcp/1086': ' cplscrambler-lg',
    'tcp/1088': ' cplscrambler-al',
    'tcp/1097': ' sunclustermgr',
    'tcp/2525': ' ms-v-worlds',
    'tcp/4242': ' vrml-multi-use',
    'tcp/8291': ' unknown',
    'tcp/9009': ' pichat',
    'tcp/52822': ' unknown',
    'tcp/900': ' omginitialrefs',
    'tcp/6101': ' backupexec',
    'tcp/2809': ' corbaloc',
    'tcp/7200': ' fodms',
    'tcp/211': ' 914c-g',
    'tcp/800': ' mdbs_daemon',
    'tcp/987': ' unknown',
    'tcp/1083': ' ansoft-lm-1',
    'tcp/12000': ' cce4x',
    'tcp/32775': ' sometimes-rpc13',
    'tcp/705': ' agentx',
    'tcp/711': ' cisco-tdp',
    'tcp/20005': ' btx',
    'tcp/6969': ' acmsoda',
    'tcp/13783': ' netbackup',
    'tcp/1045': ' fpitp',
    'tcp/1046': ' wfremotertm',
    'tcp/1057': ' startron',
    'tcp/1061': ' kiosk',
    'tcp/1063': ' kyoceranetdev',
    'tcp/1070': ' gmrupdateserv',
    'tcp/1072': ' cardax',
    'tcp/1073': ' bridgecontrol',
    'tcp/1075': ' rdrmshc',
    'tcp/1077': ' imgames',
    'tcp/1078': ' avocent-proxy',
    'tcp/1079': ' asprovatalk',
    'tcp/1081': ' pvuniwien',
    'tcp/1082': ' amt-esd-prot',
    'tcp/1085': ' webobjects',
    'tcp/1093': ' proofd',
    'tcp/1094': ' rootd',
    'tcp/1096': ' cnrprotocol',
    'tcp/1098': ' rmiactivation',
    'tcp/1099': ' rmiregistry',
    'tcp/1100': ' mctp',
    'tcp/1104': ' xrl',
    'tcp/1106': ' isoipsigport-1',
    'tcp/1107': ' isoipsigport-2',
    'tcp/1108': ' ratio-adp',
    'tcp/1148': ' elfiq-repl',
    'tcp/1169': ' tripwire',
    'tcp/1272': ' cspmlockmgr',
    'tcp/1310': ' husky',
    'tcp/1687': ' nsjtp-ctrl',
    'tcp/1718': ' h323gatedisc',
    'tcp/1783': ' unknown',
    'tcp/1840': ' netopia-vo2',
    'tcp/1947': ' sentinelsrm',
    'tcp/2100': ' amiganetfs',
    'tcp/2119': ' gsigatekeeper',
    'tcp/2135': ' gris',
    'tcp/2144': ' lv-ffx',
    'tcp/2160': ' apc-2160',
    'tcp/2190': ' tivoconnect',
    'tcp/2260': ' apc-2260',
    'tcp/2381': ' compaq-https',
    'tcp/2399': ' fmpro-fdal',
    'tcp/2492': ' groove',
    'tcp/2607': ' connection',
    'tcp/2718': ' pn-requester2',
    'tcp/2811': ' gsiftp',
    'tcp/2875': ' dxmessagebase2',
    'tcp/3017': ' event_listener',
    'tcp/3031': ' eppc',
    'tcp/3071': ' csd-mgmt-port',
    'tcp/3211': ' avsecuremgmt',
    'tcp/3300': ' ceph',
    'tcp/3301': ' unknown',
    'tcp/3323': ' active-net',
    'tcp/3325': ' active-net',
    'tcp/3351': ' btrieve',
    'tcp/3367': ' satvid-datalnk',
    'tcp/3404': ' unknown',
    'tcp/3551': ' apcupsd',
    'tcp/3580': ' nati-svrloc',
    'tcp/3659': ' apple-sasl',
    'tcp/3766': ' sitewatch-s',
    'tcp/3784': ' bfd-control',
    'tcp/3801': ' ibm-mgr',
    'tcp/3827': ' netmpi',
    'tcp/3998': ' dnx',
    'tcp/4003': ' pxc-splr-ft',
    'tcp/4126': ' ddrepl',
    'tcp/4129': ' nuauth',
    'tcp/4449': ' privatewire',
    'tcp/5030': ' surfpass',
    'tcp/5222': ' xmpp-client',
    'tcp/5269': ' xmpp-server',
    'tcp/5414': ' statusd',
    'tcp/5633': ' beorl',
    'tcp/5718': ' dpm',
    'tcp/5810': ' unknown',
    'tcp/5825': ' unknown',
    'tcp/5877': ' unknown',
    'tcp/5910': ' cm',
    'tcp/5911': ' cpdlc',
    'tcp/5925': ' unknown',
    'tcp/5959': ' unknown',
    'tcp/5960': ' unknown',
    'tcp/5961': ' unknown',
    'tcp/5962': ' unknown',
    'tcp/5987': ' wbem-rmi',
    'tcp/5988': ' wbem-http',
    'tcp/5989': ' wbem-https',
    'tcp/6123': ' backup-express',
    'tcp/6129': ' unknown',
    'tcp/6156': ' unknown',
    'tcp/6389': ' clariion-evr01',
    'tcp/6580': ' parsec-master',
    'tcp/6788': ' smc-http',
    'tcp/6901': ' jetstream',
    'tcp/7106': ' unknown',
    'tcp/7625': ' unknown',
    'tcp/7627': ' soap-http',
    'tcp/7741': ' scriptview',
    'tcp/7777': ' cbt',
    'tcp/7778': ' interwise',
    'tcp/7911': ' unknown',
    'tcp/8086': ' d-s-n',
    'tcp/8087': ' simplifymedia',
    'tcp/8181': ' intermapper',
    'tcp/8222': ' unknown',
    'tcp/8333': ' bitcoin',
    'tcp/8400': ' cvd',
    'tcp/8402': ' abarsd',
    'tcp/8600': ' asterix',
    'tcp/8649': ' unknown',
    'tcp/8873': ' dxspider',
    'tcp/8994': ' unknown',
    'tcp/9002': ' dynamid',
    'tcp/9010': ' sdr',
    'tcp/9011': ' unknown',
    'tcp/9080': ' glrpc',
    'tcp/9220': ' unknown',
    'tcp/9290': ' unknown',
    'tcp/9485': ' unknown',
    'tcp/9500': ' ismserver',
    'tcp/9502': ' unknown',
    'tcp/9503': ' unknown',
    'tcp/9618': ' condor',
    'tcp/9900': ' iua',
    'tcp/9968': ' unknown',
    'tcp/10002': ' documentum',
    'tcp/10012': ' unknown',
    'tcp/10024': ' unknown',
    'tcp/10025': ' unknown',
    'tcp/10566': ' unknown',
    'tcp/10616': ' unknown',
    'tcp/10617': ' unknown',
    'tcp/10621': ' unknown',
    'tcp/10626': ' unknown',
    'tcp/10628': ' unknown',
    'tcp/10629': ' unknown',
    'tcp/11110': ' sgi-soap',
    'tcp/11967': ' sysinfo-sp',
    'tcp/13456': ' unknown',
    'tcp/14000': ' scotty-ft',
    'tcp/14442': ' unknown',
    'tcp/15002': ' onep-tls',
    'tcp/15003': ' unknown',
    'tcp/15660': ' bex-xr',
    'tcp/16001': ' fmsascon',
    'tcp/16016': ' unknown',
    'tcp/16018': ' unknown',
    'tcp/17988': ' unknown',
    'tcp/19101': ' unknown',
    'tcp/19801': ' unknown',
    'tcp/19842': ' unknown',
    'tcp/20000': ' dnp',
    'tcp/20031': ' unknown',
    'tcp/20221': ' unknown',
    'tcp/20222': ' ipulse-ics',
    'tcp/21571': ' unknown',
    'tcp/22939': ' unknown',
    'tcp/24800': ' unknown',
    'tcp/25734': ' unknown',
    'tcp/27715': ' unknown',
    'tcp/28201': ' unknown',
    'tcp/30000': ' ndmps',
    'tcp/30718': ' unknown',
    'tcp/31038': ' unknown',
    'tcp/32781': ' unknown',
    'tcp/32782': ' unknown',
    'tcp/33899': ' unknown',
    'tcp/34571': ' unknown',
    'tcp/34572': ' unknown',
    'tcp/34573': ' unknown',
    'tcp/40193': ' unknown',
    'tcp/48080': ' unknown',
    'tcp/49158': ' unknown',
    'tcp/49159': ' unknown',
    'tcp/49160': ' unknown',
    'tcp/50003': ' unknown',
    'tcp/50006': ' unknown',
    'tcp/50800': ' unknown',
    'tcp/57294': ' unknown',
    'tcp/58080': ' unknown',
    'tcp/60020': ' unknown',
    'tcp/63331': ' unknown',
    'tcp/65129': ' unknown',
    'tcp/89': ' su-mit-tg',
    'tcp/691': ' resvc',
    'tcp/212': ' anet',
    'tcp/1001': ' webpush',
    'tcp/1999': ' tcp-id-port',
    'tcp/2020': ' xinupageserver',
    'tcp/32776': ' sometimes-rpc15',
    'tcp/2998': ' iss-realsec',
    'tcp/6003': ' X11:3',
    'tcp/7002': ' afs3-prserver',
    'tcp/50002': ' iiimsf',
    'tcp/32': ' unknown',
    'tcp/898': ' sun-manageconsole',
    'tcp/2033': ' glogger',
    'tcp/3372': ' msdtc',
    'tcp/5510': ' secureidprop',
    'tcp/99': ' metagram',
    'tcp/425': ' icad-el',
    'tcp/749': ' kerberos-adm',
    'tcp/5903': ' vnc-3',
    'tcp/43': ' whois',
    'tcp/458': ' appleqtc',
    'tcp/5405': ' pcduo',
    'tcp/6106': ' isdninfo',
    'tcp/6502': ' netop-rc',
    'tcp/7007': ' afs3-bos',
    'tcp/13722': ' netbackup',
    'tcp/1087': ' cplscrambler-in',
    'tcp/1089': ' ff-annunc',
    'tcp/1124': ' hpvmmcontrol',
    'tcp/1152': ' winpoplanmess',
    'tcp/1183': ' llsurfup-http',
    'tcp/1186': ' mysql-cluster',
    'tcp/1247': ' visionpyramid',
    'tcp/1296': ' dproxy',
    'tcp/1334': ' writesrv',
    'tcp/1580': ' tn-tl-r1',
    'tcp/1782': ' hp-hcip',
    'tcp/2126': ' pktcable-cops',
    'tcp/2179': ' vmrdp',
    'tcp/2191': ' tvbus',
    'tcp/2251': ' dif-port',
    'tcp/2522': ' windb',
    'tcp/3011': ' trusted-web',
    'tcp/3030': ' arepa-cas',
    'tcp/3077': ' orbix-loc-ssl',
    'tcp/3261': ' winshadow',
    'tcp/3369': ' satvid-datalnk',
    'tcp/3370': ' satvid-datalnk',
    'tcp/3371': ' satvid-datalnk',
    'tcp/3493': ' nut',
    'tcp/3546': ' unknown',
    'tcp/3737': ' xpanel',
    'tcp/3828': ' neteh',
    'tcp/3851': ' spectraport',
    'tcp/3871': ' avocent-adsap',
    'tcp/3880': ' igrs',
    'tcp/3918': ' pktcablemmcops',
    'tcp/3995': ' iss-mgmt-ssl',
    'tcp/4006': ' pxc-spvr',
    'tcp/4111': ' xgrid',
    'tcp/4446': ' n1-fwp',
    'tcp/5054': ' rlm-admin',
    'tcp/5200': ' targus-getdata',
    'tcp/5280': ' xmpp-bosh',
    'tcp/5298': ' presence',
    'tcp/5822': ' unknown',
    'tcp/5859': ' wherehoo',
    'tcp/5904': ' unknown',
    'tcp/5915': ' unknown',
    'tcp/5922': ' unknown',
    'tcp/5963': ' indy',
    'tcp/7103': ' unknown',
    'tcp/7402': ' rtps-dd-mt',
    'tcp/7435': ' unknown',
    'tcp/7443': ' oracleas-https',
    'tcp/7512': ' unknown',
    'tcp/8011': ' unknown',
    'tcp/8090': ' opsmessaging',
    'tcp/8100': ' xprint-server',
    'tcp/8180': ' unknown',
    'tcp/8254': ' unknown',
    'tcp/8500': ' fmtp',
    'tcp/8654': ' unknown',
    'tcp/9091': ' xmltec-xmlmail',
    'tcp/9110': ' unknown',
    'tcp/9666': ' zoomcp',
    'tcp/9877': ' unknown',
    'tcp/9943': ' unknown',
    'tcp/9944': ' unknown',
    'tcp/9998': ' distinct32',
    'tcp/10004': ' emcrmirccd',
    'tcp/10778': ' unknown',
    'tcp/15742': ' unknown',
    'tcp/16012': ' unknown',
    'tcp/18988': ' unknown',
    'tcp/19283': ' keysrvr',
    'tcp/19315': ' keyshadow',
    'tcp/19780': ' unknown',
    'tcp/24444': ' unknown',
    'tcp/27352': ' unknown',
    'tcp/27353': ' unknown',
    'tcp/27355': ' unknown',
    'tcp/32784': ' unknown',
    'tcp/49163': ' unknown',
    'tcp/49165': ' unknown',
    'tcp/49175': ' unknown',
    'tcp/50389': ' unknown',
    'tcp/50636': ' unknown',
    'tcp/51493': ' unknown',
    'tcp/55055': ' unknown',
    'tcp/56738': ' unknown',
    'tcp/61532': ' unknown',
    'tcp/61900': ' unknown',
    'tcp/62078': ' iphone-sync',
    'tcp/1021': ' exp1',
    'tcp/9040': ' tor-trans',
    'tcp/32777': ' sometimes-rpc17',
    'tcp/32779': ' sometimes-rpc21',
    'tcp/616': ' sco-sysmgr',
    'tcp/666': ' doom',
    'tcp/700': ' epp',
    'tcp/2021': ' servexec',
    'tcp/32778': ' sometimes-rpc19',
    'tcp/84': ' ctf',
    'tcp/545': ' ekshell',
    'tcp/1112': ' msql',
    'tcp/1524': ' ingreslock',
    'tcp/2040': ' lam',
    'tcp/4321': ' rwhois',
    'tcp/5802': ' vnc-http-2',
    'tcp/38292': ' landesk-cba',
    'tcp/49400': ' compaqdiag',
    'tcp/1084': ' ansoft-lm-2',
    'tcp/1600': ' issd',
    'tcp/2048': ' dls-monitor',
    'tcp/2111': ' kx',
    'tcp/3006': ' deslogind',
    'tcp/32780': ' sometimes-rpc23',
    'tcp/2638': ' sybase',
    'tcp/6547': ' powerchuteplus',
    'tcp/6699': ' napster',
    'tcp/9111': ' DragonIDSConsole',
    'tcp/16080': ' osxwebadmin',
    'tcp/555': ' dsf',
    'tcp/667': ' disclose',
    'tcp/720': ' unknown',
    'tcp/801': ' device',
    'tcp/1443': ' ies-lm',
    'tcp/1533': ' virtual-places',
    'tcp/2034': ' scoremgr',
    'tcp/2106': ' ekshell',
    'tcp/5560': ' isqlplus',
    'tcp/6007': ' X11:7',
    'tcp/1090': ' ff-fms',
    'tcp/1091': ' ff-sm',
    'tcp/1114': ' mini-sql',
    'tcp/1117': ' ardus-mtrns',
    'tcp/1119': ' bnetgame',
    'tcp/1122': ' availant-mgr',
    'tcp/1131': ' caspssl',
    'tcp/1138': ' encrypted_admin',
    'tcp/1151': ' unizensus',
    'tcp/1175': ' dossier',
    'tcp/1199': ' dmidi',
    'tcp/1201': ' nucleus-sand',
    'tcp/1271': ' excw',
    'tcp/1862': ' mysql-cm-agent',
    'tcp/2323': ' 3d-nfsd',
    'tcp/2393': ' ms-olap1',
    'tcp/2394': ' ms-olap2',
    'tcp/2608': ' wag-service',
    'tcp/2725': ' msolap-ptp2',
    'tcp/2909': ' funk-dialout',
    'tcp/3003': ' cgms',
    'tcp/3168': ' poweronnud',
    'tcp/3221': ' xnm-clear-text',
    'tcp/3322': ' active-net',
    'tcp/3324': ' active-net',
    'tcp/3390': ' dsc',
    'tcp/3517': ' 802-11-iapp',
    'tcp/3527': ' beserver-msg-q',
    'tcp/3800': ' pwgpsi',
    'tcp/3809': ' apocd',
    'tcp/3814': ' neto-dcs',
    'tcp/3826': ' wormux',
    'tcp/3869': ' ovsam-mgmt',
    'tcp/3878': ' fotogcad',
    'tcp/3889': ' dandv-tester',
    'tcp/3905': ' mupdate',
    'tcp/3914': ' listcrt-port-2',
    'tcp/3920': ' exasoftport1',
    'tcp/3945': ' emcads',
    'tcp/3971': ' lanrevserver',
    'tcp/4004': ' pxc-roid',
    'tcp/4005': ' pxc-pin',
    'tcp/4279': ' vrml-multi-use',
    'tcp/4445': ' upnotifyp',
    'tcp/4550': ' gds-adppiw-db',
    'tcp/4567': ' tram',
    'tcp/4848': ' appserv-http',
    'tcp/4900': ' hfcs',
    'tcp/5033': ' jtnetd-server',
    'tcp/5061': ' sip-tls',
    'tcp/5080': ' onscreen',
    'tcp/5087': ' biotic',
    'tcp/5221': ' 3exmp',
    'tcp/5440': ' unknown',
    'tcp/5544': ' unknown',
    'tcp/5678': ' rrac',
    'tcp/5730': ' unieng',
    'tcp/5811': ' unknown',
    'tcp/5815': ' unknown',
    'tcp/5850': ' unknown',
    'tcp/5862': ' unknown',
    'tcp/5906': ' unknown',
    'tcp/5907': ' unknown',
    'tcp/5950': ' unknown',
    'tcp/5952': ' unknown',
    'tcp/6025': ' x11',
    'tcp/6100': ' synchronet-db',
    'tcp/6510': ' mcer-port',
    'tcp/6565': ' unknown',
    'tcp/6566': ' sane-port',
    'tcp/6567': ' esp',
    'tcp/6689': ' tsa',
    'tcp/6692': ' unknown',
    'tcp/6779': ' unknown',
    'tcp/6792': ' unknown',
    'tcp/6839': ' unknown',
    'tcp/7025': ' vmsvc-2',
    'tcp/7496': ' unknown',
    'tcp/7676': ' imqbrokerd',
    'tcp/7800': ' asr',
    'tcp/7920': ' unknown',
    'tcp/7921': ' unknown',
    'tcp/7999': ' irdmi2',
    'tcp/8022': ' oa-system',
    'tcp/8042': ' fs-agent',
    'tcp/8045': ' unknown',
    'tcp/8093': ' unknown',
    'tcp/8099': ' unknown',
    'tcp/8200': ' trivnet1',
    'tcp/8290': ' unknown',
    'tcp/8292': ' blp3',
    'tcp/8300': ' tmi',
    'tcp/8383': ' m2mservices',
    'tcp/8800': ' sunwebadmin',
    'tcp/9003': ' unknown',
    'tcp/9081': ' unknown',
    'tcp/9099': ' unknown',
    'tcp/9200': ' wap-wsp',
    'tcp/9418': ' git',
    'tcp/9575': ' unknown',
    'tcp/9878': ' kca-service',
    'tcp/9898': ' monkeycom',
    'tcp/9917': ' unknown',
    'tcp/10003': ' documentum_s',
    'tcp/10009': ' swdtp-sv',
    'tcp/10180': ' unknown',
    'tcp/10215': ' unknown',
    'tcp/11111': ' vce',
    'tcp/12174': ' unknown',
    'tcp/12265': ' unknown',
    'tcp/14441': ' unknown',
    'tcp/15004': ' unknown',
    'tcp/16000': ' fmsas',
    'tcp/16113': ' unknown',
    'tcp/17877': ' unknown',
    'tcp/18040': ' unknown',
    'tcp/18101': ' unknown',
    'tcp/19350': ' unknown',
    'tcp/25735': ' unknown',
    'tcp/26214': ' unknown',
    'tcp/27356': ' unknown',
    'tcp/30951': ' unknown',
    'tcp/32783': ' unknown',
    'tcp/32785': ' unknown',
    'tcp/40911': ' unknown',
    'tcp/41511': ' unknown',
    'tcp/44176': ' unknown',
    'tcp/44501': ' unknown',
    'tcp/49161': ' unknown',
    'tcp/49167': ' unknown',
    'tcp/49176': ' unknown',
    'tcp/50300': ' unknown',
    'tcp/50500': ' unknown',
    'tcp/52673': ' unknown',
    'tcp/52848': ' unknown',
    'tcp/54045': ' unknown',
    'tcp/54328': ' unknown',
    'tcp/55056': ' unknown',
    'tcp/56737': ' unknown',
    'tcp/57797': ' unknown',
    'tcp/60443': ' unknown',
    'tcp/70': ' gopher',
    'tcp/417': ' onmux',
    'tcp/617': ' sco-dtmgr',
    'tcp/714': ' iris-xpcs',
    'tcp/722': ' unknown',
    'tcp/777': ' multiling-http',
    'tcp/981': ' unknown',
    'tcp/1009': ' unknown',
    'tcp/2022': ' down',
    'tcp/4224': ' xtell',
    'tcp/4998': ' maybe-veritas',
    'tcp/6346': ' gnutella',
    'tcp/301': ' unknown',
    'tcp/524': ' ncp',
    'tcp/668': ' mecomm',
    'tcp/765': ' webster',
    'tcp/1076': ' sns_credit',
    'tcp/2041': ' interbase',
    'tcp/5999': ' ncd-conf',
    'tcp/10082': ' amandaidx',
    'tcp/259': ' esro-gen',
    'tcp/416': ' silverplatter',
    'tcp/1007': ' unknown',
    'tcp/1417': ' timbuktu-srv1',
    'tcp/1434': ' ms-sql-m',
    'tcp/1984': ' bigbrother',
    'tcp/2038': ' objectmanager',
    'tcp/2068': ' avocentkvm',
    'tcp/4343': ' unicall',
    'tcp/6009': ' X11:9',
    'tcp/7004': ' afs3-kaserver',
    'tcp/44443': ' coldfusion-auth',
    'tcp/109': ' pop2',
    'tcp/687': ' asipregistry',
    'tcp/726': ' unknown',
    'tcp/911': ' xact-backup',
    'tcp/1010': ' surf',
    'tcp/1461': ' ibm_wrless_lan',
    'tcp/2035': ' imsldoc',
    'tcp/2046': ' sdfunc',
    'tcp/4125': ' rww',
    'tcp/6006': ' X11:6',
    'tcp/7201': ' dlip',
    'tcp/9103': ' jetdirect',
    'tcp/125': ' locus-map',
    'tcp/481': ' dvs',
    'tcp/683': ' corba-iiop',
    'tcp/903': ' iss-console-mgr',
    'tcp/1011': ' unknown',
    'tcp/1455': ' esl-lm',
    'tcp/2013': ' raid-am',
    'tcp/2043': ' isis-bcast',
    'tcp/2047': ' dls',
    'tcp/6668': ' irc',
    'tcp/6669': ' irc',
    'tcp/256': ' fw1-secureremote',
    'tcp/406': ' imsp',
    'tcp/783': ' spamassassin',
    'tcp/843': ' unknown',
    'tcp/2042': ' isis',
    'tcp/2045': ' cdfunc',
    'tcp/5998': ' ncd-diag',
    'tcp/9929': ' nping-echo',
    'tcp/31337': ' Elite',
    'tcp/44442': ' coldfusion-auth',
    'tcp/1092': ' obrpd',
    'tcp/1095': ' nicelink',
    'tcp/1102': ' adobeserver-1',
    'tcp/1105': ' ftranhc',
    'tcp/1113': ' ltp-deepspace',
    'tcp/1121': ' rmpp',
    'tcp/1123': ' murray',
    'tcp/1126': ' hpvmmdata',
    'tcp/1130': ' casp',
    'tcp/1132': ' kvm-via-ip',
    'tcp/1137': ' trim',
    'tcp/1141': ' mxomss',
    'tcp/1145': ' x9-icue',
    'tcp/1147': ' capioverlan',
    'tcp/1149': ' bvtsonar',
    'tcp/1154': ' resacommunity',
    'tcp/1163': ' sddp',
    'tcp/1164': ' qsm-proxy',
    'tcp/1165': ' qsm-gui',
    'tcp/1166': ' qsm-remote',
    'tcp/1174': ' fnet-remote-ui',
    'tcp/1185': ' catchpole',
    'tcp/1187': ' alias',
    'tcp/1192': ' caids-sensor',
    'tcp/1198': ' cajo-discovery',
    'tcp/1213': ' mpc-lifenet',
    'tcp/1216': ' etebac5',
    'tcp/1217': ' hpss-ndapi',
    'tcp/1233': ' univ-appserver',
    'tcp/1236': ' bvcontrol',
    'tcp/1244': ' isbconference1',
    'tcp/1259': ' opennl-voice',
    'tcp/1277': ' miva-mqs',
    'tcp/1287': ' routematch',
    'tcp/1300': ' h323hostcallsc',
    'tcp/1301': ' ci3-software-1',
    'tcp/1309': ' jtag-server',
    'tcp/1322': ' novation',
    'tcp/1328': ' ewall',
    'tcp/1556': ' veritas_pbx',
    'tcp/1583': ' simbaexpress',
    'tcp/1594': ' sixtrak',
    'tcp/1641': ' invision',
    'tcp/1658': ' sixnetudr',
    'tcp/1688': ' nsjtp-data',
    'tcp/1719': ' h323gatestat',
    'tcp/1721': ' caicci',
    'tcp/1805': ' enl-name',
    'tcp/1812': ' radius',
    'tcp/1839': ' netopia-vo1',
    'tcp/1875': ' westell-stats',
    'tcp/1914': ' elm-momentum',
    'tcp/1971': ' netop-school',
    'tcp/1972': ' intersys-cache',
    'tcp/1974': ' drp',
    'tcp/2099': ' h2250-annex-g',
    'tcp/2170': ' eyetv',
    'tcp/2196': ' unknown',
    'tcp/2200': ' ici',
    'tcp/2288': ' netml',
    'tcp/2366': ' qip-login',
    'tcp/2382': ' ms-olap3',
    'tcp/2557': ' nicetec-mgmt',
    'tcp/2710': ' sso-service',
    'tcp/2800': ' acc-raid',
    'tcp/2910': ' tdaccess',
    'tcp/2920': ' roboeda',
    'tcp/2968': ' enpp',
    'tcp/3007': ' lotusmtap',
    'tcp/3013': ' gilatskysurfer',
    'udp/631': ' ipp',
    'udp/161': ' snmp',
    'udp/137': ' netbios-ns',
    'udp/123': ' ntp',
    'udp/138': ' netbios-dgm',
    'udp/1434': ' ms-sql-m',
    'udp/445': ' microsoft-ds',
    'udp/135': ' msrpc',
    'udp/67': ' dhcps',
    'udp/53': ' domain',
    'udp/139': ' netbios-ssn',
    'udp/500': ' isakmp',
    'udp/68': ' dhcpc',
    'udp/520': ' route',
    'udp/1900': ' upnp',
    'udp/4500': ' nat-t-ike',
    'udp/514': ' syslog',
    'udp/49152': ' unknown',
    'udp/162': ' snmptrap',
    'udp/69': ' tftp',
    'udp/5353': ' zeroconf',
    'udp/111': ' rpcbind',
    'udp/49154': ' unknown',
    'udp/1701': ' L2TP',
    'udp/998': ' puparp',
    'udp/996': ' vsinet',
    'udp/997': ' maitrd',
    'udp/999': ' applix',
    'udp/3283': ' netassistant',
    'udp/49153': ' unknown',
    'udp/1812': ' radius',
    'udp/136': ' profile',
    'udp/2222': ' msantipiracy',
    'udp/2049': ' nfs',
    'udp/32768': ' omad',
    'udp/5060': ' sip',
    'udp/1025': ' blackjack',
    'udp/1433': ' ms-sql-s',
    'udp/3456': ' IISrpc-or-vat',
    'udp/80': ' http',
    'udp/20031': ' bakbonenetvault',
    'udp/1026': ' win-rpc',
    'udp/7': ' echo',
    'udp/1646': ' radacct',
    'udp/1645': ' radius',
    'udp/593': ' http-rpc-epmap',
    'udp/518': ' ntalk',
    'udp/2048': ' dls-monitor',
    'udp/626': ' serialnumberd',
    'udp/1027': ' unknown',
    'udp/177': ' xdmcp',
    'udp/1719': ' h323gatestat',
    'udp/427': ' svrloc',
    'udp/497': ' retrospect',
    'udp/4444': ' krb524',
    'udp/1023': ' unknown',
    'udp/65024': ' unknown',
    'udp/19': ' chargen',
    'udp/9': ' discard',
    'udp/49193': ' unknown',
    'udp/1029': ' solid-mux',
    'udp/49': ' tacacs',
    'udp/88': ' kerberos-sec',
    'udp/1028': ' ms-lsa',
    'udp/17185': ' wdbrpc',
    'udp/1718': ' h225gatedisc',
    'udp/49186': ' unknown',
    'udp/2000': ' cisco-sccp',
    'udp/31337': ' BackOrifice',
    'udp/49192': ' unknown',
    'udp/49201': ' unknown',
    'udp/515': ' printer',
    'udp/2223': ' rockwell-csp2',
    'udp/443': ' https',
    'udp/49181': ' unknown',
    'udp/1813': ' radacct',
    'udp/120': ' cfdptkt',
    'udp/158': ' pcmail-srv',
    'udp/49200': ' unknown',
    'udp/3703': ' adobeserver-3',
    'udp/32815': ' unknown',
    'udp/17': ' qotd',
    'udp/5000': ' upnp',
    'udp/32771': ' sometimes-rpc6',
    'udp/33281': ' unknown',
    'udp/1030': ' iad1',
    'udp/623': ' asf-rmcp',
    'udp/1022': ' exp2',
    'udp/32769': ' filenet-rpc',
    'udp/5632': ' pcanywherestat',
    'udp/10000': ' ndmp',
    'udp/49156': ' unknown',
    'udp/49182': ' unknown',
    'udp/49191': ' unknown',
    'udp/49194': ' unknown',
    'udp/9200': ' wap-wsp',
    'udp/30718': ' unknown',
    'udp/49185': ' unknown',
    'udp/49188': ' unknown',
    'udp/49190': ' unknown'
}

class MasscanTargetReport():

    def __init__(self, target=None, service_info=None):
        '''initializes the object'''
        self.target_network = target
        self.hosts = []
        for h in self.target_network.hosts():
            self.hosts.append(h)
        
        # self.hosts is empty if target is a single host
        if len(self.hosts) == 0:
            self.address_min = target.network_address
            self.address_max = target.network_address
        else:
            self.address_min = min(self.hosts)
            self.address_max = max(self.hosts)
        self.open_tcp = set()
        self.open_udp = set()
        self.service_information = service_info

    def __repr__(self):
        result = "Masscan Report:\n"
        result += "Target Network: %s\n" % str(self.target_network)
        result += "Open TCP Ports:\n"
        result += ", ".join(str(x) for x in sorted(self.open_tcp)) + "\n"
        result += "Open UDP Ports:\n"
        result += ", ".join(str(x) for x in sorted(self.open_udp)) + "\n"
        result += "Unique Service Detections:\n"
        
        if self.service_information is not None:
            service_detections = {}
            for h in self.hosts:
                service_info = self.service_information.get_service_info(h)
                if service_info is not None:
                    # service_info = {'tcp/22': ['open', 'ssh', 'OpenSSH ...'], }
                    for port in sorted(service_info.keys()):
                        service_string = "%s:%s:%s" % (service_info[port][0],
                                                    service_info[port][1],
                                                    service_info[port][2])
                        if port not in service_detections:
                            service_detections[port] = set()
                            service_detections[port].add(service_string)
                        else:
                            service_detections[port].add(service_string)
            # report on TCP service detections
            for port in sorted(self.open_tcp):
                port_string = "tcp/%s" % port
                if port_string in service_detections.keys():
                    result += "%s:\n" % port_string
                    for s in sorted(service_detections[port_string]):
                        result += "\t%s\n" % (s)
            
            # report on UDP service detections
            for port in sorted(self.open_udp):
                port_string = "udp/%s" % port
                if port_string in service_detections.keys():
                    result += "%s:\n" % port_string
                    for s in sorted(service_detections[port_string]):
                        result += "\t%s\n" % (s)

        return result
    
    def dictionary(self):
        """field_names = {'target', 'source', 'open_ports_tcp', 'open_ports_udp'}"""
        tcp_string = [str(x) for x in sorted(self.open_tcp)]
        udp_string = [str(x) for x in sorted(self.open_udp)]
        data_dict = {
            'target': str(self.target_network),
            'source': '',
            'open_ports_tcp': "; ".join(tcp_string),
            'open_ports_udp': "; ".join(udp_string)
        }
        return data_dict
        
    def contains(self, target):
        '''returns true if the source and target networks are the same, 
        otherwise, returns false. Target must be an IPv4Address object.
        '''
        result = False
        if self.address_min <= target <= self.address_max:
            result = True
        return result

    def add_port(self, protocol, port):
        '''adds a port to the object'''
        if protocol.lower() == 'tcp':
            self.open_tcp.add(int(port))
        elif protocol.lower() == 'udp':
            self.open_udp.add(int(port))

    def has_open_ports(self):
        result = True
        if len(self.open_tcp) == 0 and len(self.open_udp) == 0:
            result = False
        return result


class ServiceInformation:
    # data structure for storing service detections
    def __init__(self):
        self.service_information = {}
    
    def __repr__(self):
        result = "Service Information:\n"
        for k in sorted(self.service_information.keys()):
            result += "%s\n" % (self.service_information[k])
        return result

    def read_gnmap(self, file_path):
        with open(file_path, "r") as fd:
            lines = fd.readlines()
        
        for l in lines:
            if "Ports" in l:
                host_part, port_part = l.split("\t")
                _, ip, _ = host_part.split(" ")
                _, port_info = port_part.split("Ports: ")
                port, status, proto, _, service, _, service_info, _ = port_info.split("/")
                self.add_service_info(ip, proto, port, status, service, service_info)

    def add_service_info(self, ip, proto, port, status, service, service_info):
        # use the integer representation of the ip address
        # for fast dictionary lookups
        ip = int(ipaddress.IPv4Address(ip))
        port_str = "%s/%s" % (proto, port)
        port_info = {port_str: [status, service, service_info]}
        if ip not in self.service_information.keys():
            self.service_information[ip] = port_info
        else:
            self.service_information[ip][port_str] = [status, service, service_info]
    
    def get_service_info(self, ip):
        ip_int = int(ip)
        result = None
        if ip_int in self.service_information.keys():
            result = self.service_information[ip_int]
        
        return result

    def get_all_service_info(self):
        """returns a list of dicts, each dict having
        {ip, proto, port, status, service, service_info}"""
        result = []

        for k in self.service_information.keys():
            ip = k
            for p in self.service_information[k].keys():
                proto, port = p.split("/")
                service_list = self.service_information[k][p]
                status = service_list[0]
                service = service_list[1]
                service_info = service_list[2]
                result.append({
                    'ip': str(ipaddress.IPv4Address(ip)), 
                    'proto': proto, 
                    'port': port, 
                    'status': status, 
                    'service': service,
                    'service_info': service_info
                    })

        return result


def main():
    '''main function'''
    masscan_reports = []  # there will be one masscan report per target network
    target_nets = []
    service_info = None

    # open and read data from the targets file
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", nargs="?", help="service detection directory")
    parser.add_argument("-c", nargs="?", help="csv summary output file")
    parser.add_argument("-C", nargs="?", help="csv detail output file")
    parser.add_argument("target_file", nargs=1, help="targets text file")
    parser.add_argument("masscan_file", nargs=1, help="masscan file")
    args = parser.parse_args()

    targets_file = args.target_file[0]
    masscan_results_file = args.masscan_file[0]
    service_detect_dir = args.s
    csv_output = args.c
    csv_detail_output = args.C

    # open the targets file
    with open(targets_file, 'r') as targets_fd:
        lines = targets_fd.read().split('\n')

    # add each network to the list of target_nets
    while '' in lines:
        # remove blank lines
        lines.remove('')

    # add all networks to the list of target_nets
    for l in lines:
        l = l.strip()
        if '#' in l[0]:
            # comment
            continue
        elif '/' in l:
            # network specification
            network = ipaddress.IPv4Network(l, strict=False)
        else:
            network = ipaddress.IPv4Network(l + "/32", strict=False)
        
        if network not in target_nets:
            target_nets.append(network)
    
    # gather service information
    service_info = None
    if service_detect_dir is not None:
        service_info = ServiceInformation()
        for f in os.listdir(service_detect_dir):
            if f.endswith(".gnmap"):
                file_path = os.path.join(service_detect_dir, f)
                service_info.read_gnmap(file_path)

    print("target nets:")
    for t in target_nets:
        r = MasscanTargetReport(t, service_info)
        masscan_reports.append(r)
        print(str(t))

    # read and process the masscan input file
    service_info_list = []
    with open(masscan_results_file) as masscan_fd:
        masscan_lines = masscan_fd.read().splitlines()
        total_lines = len(masscan_lines)
        for i, line in enumerate(masscan_lines):
            if i % 1000 == 0:
                print("[*] processed %i/%i lines" % (i, total_lines))
            if 'open' in line:
                port_status, protocol, port, destination, _ = line.split(" ")

                destination = ipaddress.IPv4Address(destination)
                for m in masscan_reports:
                    if m.contains(destination):
                        m.add_port(protocol, port)

                if service_info is None:
                    # add to service_info_dict for later use
                    service_key = '%s/%s' % (protocol, port)
                    if service_key in SERVICE_DB.keys():
                        service = SERVICE_DB[service_key]
                    else:
                        service = ""
                    service_data = {
                        'ip': destination,
                        'proto': protocol,
                        'port': port,
                        'status': port_status,
                        'service': service,
                        'service_info': ""
                    }
                    service_info_list.append(service_data)

    # print each masscan report after sorting, primarily by source, secondarily by target
    s = sorted(masscan_reports, key=attrgetter('target_network'))
    for r in s:
        if r.has_open_ports():
            print(r)
    
    # output to CSV if desired
    if csv_output is not None:
        csv_fd = open(csv_output, 'w', newline='')
        field_names = ['target', 'source', 'open_ports_tcp', 'open_ports_udp']
        csv_writer = csv.DictWriter(csv_fd, fieldnames=field_names)
        csv_writer.writeheader()
        for r in s:
            if r.has_open_ports():
                data = r.dictionary()
                data['source'] = os.path.basename(masscan_results_file)
                csv_writer.writerow(data)
        csv_fd.close()

    if csv_detail_output is not None:
        if service_info is not None:
            service_info_list = service_info.get_all_service_info()
        
        csv_fd = open(csv_detail_output, 'w', newline='')
        field_names = ['ip', 'proto', 'port', 'status', 'service', 'service_info']
        csv_writer = csv.DictWriter(csv_fd, fieldnames=field_names)
        csv_writer.writeheader()
        for s in service_info_list:
            csv_writer.writerow(s)
        csv_fd.close()


def print_help():
    '''prints a message that indicates how to use this program'''
    print("""Usage: masscan_report.py <targets file> <masscan list file>
Optional arguments:
   -s <service detection directory>
   -c <csv summary output file>
   -C <csv detail output file>""")


if __name__ == "__main__":
    main()
