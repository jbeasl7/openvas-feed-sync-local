# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb:
# - Syntax is the following:
#   username:password:vendor:protocol
# - Multiple vendors are separated by ","
# - Multiple protocols are also separated by ","
# - Current available options for the 'protocol' string: all,ssh,http,ftp
# - 'all' doesn't include 'ftp' because we currently don't want to run
#   gb_default_ftp_credentials.nasl against all credentials defined below
# - The string "<<none>>" can be used for testing an empty username or password
#
credentials = make_list(
"root:pass:axis:all,ftp",

# nb:
# - Generally a default password
# - CVE-2006-5288: Cisco 2700 Series Wireless Location Appliances before 2.1.34.0 have a default administrator username "root" and password "password"
# - CVE-2012-4577: The Linux firmware image on (1) Korenix Jetport 5600 series serial-device servers and (2) ORing Industrial DIN-Rail serial-device servers has a hardcoded password of "password" for the root account
"root:password:korenix,cisco,oring:all,ftp,ssh",

"MGR:REGO:hp:all",
"MAIL:TELESUP:hp:all",
"storwatch:specialist:ibm:all",
"admin:hp.com:hp:all",
"user:public:compaq:all,ftp",
"MGR:HPP196:hp:all",
"at4400:at4400:alcatel:all",
"FIELD:HPWORD PUB:hp:all",
"root:letacla:alcatel:all",
"HELLO:MGR.SYS:hp:all",
"mtch:mtch:alcatel:all",
"User:<<none>>:bay networks,dlink:all",
"device:device:apc:all,ftp",
"cisco:cisco:cisco:all,ftp",
"Administrator:admin:cisco,conexant,corecess,gvc:all",
"MANAGER:COGNOS:hp:all",
"MAIL:HPOFFICE:hp:all",
"admin:diamond:cisco:all",
"patrol:patrol:bmc:all",
"MAIL:MAIL:hp:all",
"admin:changeme:cisco:all,ftp",
"admin:default:cisco:all,ftp",
"dhs3pms:dhs3pms:alcatel:all",
"root:Mau'dib:celerity:all",
"login:password:efficient:all,ftp",
"PFCUser:240653C9467E45:compaq:all",
"Administrator:letmein:integral:all",
"davox:davox:davox:all",
"debug:synnet:3com:all",
"MANAGER:SECURITY:hp:all",
"FIELD:SERVICE:hp:all",
"sa:<<none>>:cisco,davox:all",
"Cisco:Cisco:cisco:all",
"root:attack:cisco:all",
"guest:<<none>>:cisco,edimax,intel:all",
"MGR:CONV:hp:all",
"MANAGER:TELESUP:hp:all",
"volition:volition:3m:all",
"administrator:administrator:compaq:all,ftp",
"FIELD:HPP187 SYS:hp:all",
"cmaker:cmaker:cisco:all",
"OPERATOR:DISC:hp:all",
"OPERATOR:SUPPORT:hp:all",
"admin:synnet:3com:all",
"SYSDBA:masterkey:interbase:all",
"PBX:PBX:dictaphone:all",
"apc:apc:apc:all",
"acc:acc:andover controls:all",
"root:tslinux:cyclades:all",
"tech:tech:3com:all",
"root:ascend:ascend:all",
"operator:<<none>>:3com:all",
"FIELD:MANAGER:hp:all",
"MGR:WORD:hp:all",
"root:root:ambit,avaya,huawei:all,ftp",
"OPERATOR:COGNOS:hp:all",
"super:surt:cyclades:all",
"netrangr:attack:cisco:all",
"install:llatsni:alcatel:all",
"Manager:<<none>>:bay networks:all",
"admin:hello:intel,shiva:all",
"admin:bintec:bintec:all",
"craft:<<none>>:avaya:all",
"MGR:TELESUP:hp:all",
"manager:manager:3com:all",
"MANAGER:TCH:hp:all",
"cgadmin:cgadmin:cyberguard:all",
"adm:<<none>>:3com:all",
"monitor:monitor:3com:all",
"MGR:VESOFT:hp:all",
"admin:my_DEMARC:demarc:all",
"WP:HPOFFICE:hp:all",
"manager:friend:Allied:all",
"diag:switch:alcatel:all",
"Anonymous:<<none>>:compaq,hp:all",
"root:davox:davox:all",
"MANAGER:HPOFFICE:hp:all",
"MGR:HPOFFICE:hp:all",
"Guest:<<none>>:intel:all",
"admin:radius:funk software:all",
"security:security:3com,bay networks:all",
"admin:epicrouter:e-tech:all",
"supervisor:supervisor:everfocus:all",
"MGR:RJE:hp:all",
"MAIL:MPE:hp:all",
"root:<<none>>:3com,allied,buffalo,intel:all",
"DTA:TJM:aspect:all",
"admin:cisco:cisco:all,ftp",
"NICONEX:NICONEX:intel:all",
"MGR:ROBELLE:hp:all",
"FIELD:SUPPORT:hp:all",
"FIELD:HPONLY:hp:all",
"MGR:CNAS:hp:all",
"RSBCMON:SYS:hp:all",
"HELLO:OP.OPERATOR:hp:all",
"NETWORK:NETWORK:dictaphone:all",
"admin:linga:alteon:all",
"admin:switch:alcatel:all,ftp",
"hscroot:abc123:ibm:all",

# e.g. CVE-2018-19063
"admin:<<none>>:3com,aceex,alteon,telekom,dlink,enterasys,extreme networks,fortinet,hp,ibm,intel,foscam,opticam,ricoh:all",

"Administrator:the same all over:bmc:all",
"MGR:XLSERVER:hp:all",
"HELLO:MANAGER.SYS:hp:all",
"kermit:kermit:alcatel:all",
"MGR:CAROLIAN:hp:all",
"ADVMAIL:HP:hp:all",

# nb:
# - The origin is currently unclear
# - Initially "all" was used but the uppercase user name indicated that this is HTTP only so this
#   was changed accordingly
"D-Link:D-Link:dlink:http",

"MDaemon:MServer:deerfield:all",
"MGR:ITF3000:hp:all",
"admin:netadmin:enterasys:all",
"admin:secure:ADIC:all",
"admin:system:cisco:all",
"tech:<<none>>:3com:all",
"customer:<<none>>:aspect:all",
"MGR:SYS:hp:all",
"MGR:NETBASE:hp:all",
"bbsd-client:changeme2:cisco:all",
"user:user:compaq:all,ftp",
"vt100:public:ibm:all",
"root:ROOT500:avaya:all",
"cellit:cellit:cellit:all",
"anonymous:<<none>>:compaq:all",
"netman:<<none>>:cabletron:all",
"Administrator:<<none>>:3com:all",
"MAIL:REMOTE:hp:all",
"manager:admin:allied:all,ftp",
"intel:intel:intel:all",
"MGR:SECURITY:hp:all",
"MGR:HPP189:hp:all",
"operator:operator:compaq,everfocus:all",
"mediator:mediator:celerity:all",
"MGR:HPDESK:hp:all",
"adminttd:adminttd:3com:all",
"sysadm:anicust:accelerated networks:all",
"setup:setup:intel:all",
"HELLO:FIELD.SUPPORT:hp:all",
"mtcl:mtcl:alcatel:all",
"MGR:CCC:hp:all",
"bbsd-client:null:cisco:all",
"root:cms500:avaya:all",
"admin:comcomcom:3com:all",
"MANAGER:ITF3000:hp:all",
"admin:password:3com,adic,brocade,ciphertrust,ibm,ricoh:all,ftp",
"OPERATOR:SYSTEM:hp:all",
"IntraStack:Asante:asante:all",
"MGR:INTX3:hp:all",
"Root:<<none>>:3com,ambit:all",

# For Edimax see e.g.:
# - CVE-2004-1791: https://web.archive.org/web/20210120100703/http://www.securityfocus.com/archive/1/349089
# - https://www.exploit-db.com/exploits/38056 ("4/ Unprotected files" section shows the creds as well for BR6228nS/BR6228nC devices)
# - BR6228nS, BR6228nC, BR6428n, BR6258n and BR-6574N devices have been seen as affected as well
# - https://www.akamai.com/blog/security-research/march-edimax-cameras-command-injection-mirai (Text parts shows them as well)
"admin:1234:edimax,tplink:all,ftp,http",

"root:tini:dallas semiconductors:all",
"FIELD:MGR:hp:all",
"anonymous:any@:datawizard.net:all",
"Administrator:changeme:cisco:all",
"FIELD:LOTUS:hp:all",
"root:permit:alcatel:all",
"adfexc:adfexc:alcatel:all",
"root:default:f5:all,ftp",
"halt:tlah:alcatel:all",
"MGR:HPP187:hp:all",
"PCUSER:SYS:hp:all",
"readonly:lucenttech2:ascend:all",
"SPOOLMAN:HPOFFICE:hp:all",
"MGR:HPONLY:hp:all",
"MANAGER:SYS:hp:all",
"diag:danger:avaya:all",
"user:<<none>>:dlink:all",
"craft:crftpw:avaya:all",
"login:admin:efficient:all,ftp",
"admin:admin:huawei,3com,allied,alteon,amitech,billon,checkpoint,cisco,com3,davox,dlink,draytek,dynalink,everfocus,flowpoint,foundry networks,hp,ibm,intel,ivanti:all,http,ssh,ftp",
"client:client:alcatel:all",
"OPERATOR:SYS:hp:all",
"MGR:COGNOS:hp:all",
"manuf:xxyyzz:avaya:all",
"3comcso:RIP000:3com:all",
"dhs3mt:dhs3mt:alcatel:all",
"ADVMAIL:HPOFFICE DATA:hp:all",
"superadmin:secret:ibm:all",
"superuser:<<none>>:asante:all",
"recovery:recovery:3com:all",
"NETOP:<<none>>:dictaphone:all",
"IntraSwitch:Asante:asante:all",
"cisco:<<none>>:cisco:all",
"rwa:rwa:accelar:all",
"admin:PASS:Lantronix:all",
"TANDBERG:<<none>>:Tandberg:all",
"skyboxview:skyboxview:SkyBOX:all",

# Ivanti Cloud Services Appliance (CSA)
#
# nb:
# - this product has also "admin:admin" but these credentials are already tested above
# - while "service:admin" seems to be only a default for HTTP according to some docs but:
#  - it might be changed during the initial login
#  - the same credentials could be also valid for other products so "all,ssh,http" was used
"service:admin:ivanti:all,ssh,http",

# nb: SSH is covered in a dedicated VT: 2021/raspberrypi/gb_raspberrypi_ssh_default_credentials.nasl
"pi:raspberry:raspberry:ftp",

"root:toor:kali linux,backtrack linux:all,ftp",
"msfadmin:msfadmin:metasploitable:ssh,ftp",
"root:abcd1234:trango:all,ftp",
"root:nutanix/4u:nutanix:ssh",
"postgres:postgres:metasploitable,various:all,ssh,ftp",
"service:service:metasploitable,various:all,ssh,ftp",
"vagrant:vagrant:metasploitable,various:all,ssh,ftp",

# Mentioned on various resources like e.g.:
# - https://open-sez.me/default-passwords-ericsson.html
# - https://www.passwordsdatabase.com/vendor/ericsson
#
# and seems to be valid for these products:
# - Ericsson ACC WiFi devices
# - General Ericsson router devices
#
# as well as for these protocols:
# - HTTP Basic auth (covered here): https://images.app.goo.gl/N2txinvp4yK9t5LHA
# - HTTP Form based login (not covered here / with the relevant brute force VT):
#   https://images.app.goo.gl/UvZ8ixNUo5s1M1t47
# - Additional resources are also indicating that SSH can be enabled on at least router devices
#
# nb: In the past also "public:none" was included. But all done research have lead to the conclusion
# that this was a SNMP community which is already checked separately.
"netman:netman:ericsson:ssh,http",

# foo:$apr1$qdSLixxe$4syV8RRHWSSsvo8Gu6rZ.1 from user file of wazuh-api
"foo:bar:wazuh:http",

# For e.g. the Tomcat installation on the Metasploitable 2 VM
"tomcat:tomcat:tomcat,metasploitable:http",

# From CVE-2018-19064
"ftpuser1:<<none>>:foscam,opticam:ftp",

# From CVE-2013-7404
"insite:2getin:GEHealthcare:telnet,ftp",

# From CVE-2001-1594
"entegra:0:GEHealthcare:ftp",

# Those are credentials commonly shared across IPMI, SSH and Redfish API on various BMC devices
# nb: No need to add a "http" one here as the Redfish API is separately tested in / via:
# gsf/2024/gb_redfish_api_http_default_credentials.nasl
"ADMIN:ADMIN:supermicro:ssh",
"root:0penBmc:nvidia,dell,ibm,openbmc:ssh",
"Administrator:Admin@9000:huawei:ssh",
"administrator:DefaultFactoryPassword:hpe:ssh",
"root:calvin:dell:all",
"administrator:advantech:advantech:ssh",
"root:superuser:various:ssh",
"root:Huawei12#$:huawei:ssh",
"sysadmin:P@ssw0rd:veritas:ssh",
"root:p@ssw0rd:intel:ssh",

# Ubiquiti EdgeMax / EdgeRouter
# see https://help.ui.com/hc/en-us/articles/204976374-EdgeRouter-User-Accounts
"ubnt:ubnt:ubiquiti:ssh,telnet",

# If the default docker command from:
# https://sdk.collaboraonline.com/docs/installation/CODE_Docker_image.html
# is used.
# nb:
# - Availability check of the Basic Auth protected admin backend is done via
#   gb_collabora_libreoffice_online_http_detect.nasl
# - Might be used by other systems as well so "all" and a few other protocols are used here
"admin:S3cRet:collabora,various:all,ssh,http,ftp",

# Crestron AM-100 devices from https://www.exploit-db.com/exploits/40813
# nb:
# - No "live" system available so this was added here to have at least some basic coverage
# - Password might also refer to `Awind Inc.` and this might catch additional devices we won't get a
#   hand on
"root:awind5885:crestron,awind:ssh,telnet",

# From CVE-2020-9473
"ftp:<<none>>:siedle:ssh",

# From CVE-2017-8218
"guest:guest:tplink:ftp",

# From CVE-2017-8218 (ftp) and CVE-2024-46328 (http)
# nb: As these might exist on all services all are tested accordingly
"test:test:tplink,vonets:all,http,ssh,ftp",

# For CVE-2024-22902 from https://blog.leakix.net/2024/01/vinchin-backup-rce-chain/#default-ssh-root-credentials-cve-2024-22902
"root:Backup@3R:Vinchin:ssh",

# From CVE-2014-9198
# nb: Credentials were extracted from the java .class file
# see https://blog.qualys.com/vulnerabilities-threat-research/2015/01/23/multiple-vulnerabilities-detected-in-schneider-factorycast-hmi-gateway
"sysdiag:factorycast@schneider:schneider electric:ftp",

# From CVE-2016-8731
"r:r:foscam:ftp",

# From CVE-2018-9068. The default credentials are mentioned several times in the documentation, but
# no direct reference to FTP
"USERID:PASSW0RD:ibm,lenovo:all,ftp",

# From CVE-2015-7261, found in:
# https://labs.nettitude.com/blog/qnap-signage-station-publish-and-be-damned-part-2/
"SignageUser:joxu06wj/:qnap:ftp",

# Cisco Smart Licensing Utility (CVE-2024-20439), see e.g.:
# - https://isc.sans.edu/diary/31782?n
# - https://starkeblog.com/cve-wednesday/cisco/2024/09/20/cve-wednesday-cve-2024-20439.html
"cslu-windows-client:Library4C$LU:cisco:http",

# SolarWinds Web Help Desk (WHD) (CVE-2024-28987), see e.g.:
# - gsf/2024/solarwinds/gb_web_help_desk_hardcoded_creds_vuln_aug24_active.nasl
# - https://isc.sans.edu/diary/31782?n
"helpdeskIntegrationUser:dev-C4F8025E7:solarwinds:http",

# VONETS VAP11G-300 (CVE-2018-17771), see:
# https://dd80b675424c132b90b3-e48385e382d2e5d17821a5e1d8e4c86b.ssl.cf1.rackcdn.com/external/posworld.pdf
"ftpuser:123456:ingenico:ftp",
"maint:51966:ingenico:ftp",
"system:31415926:ingenico:ftp",

# From CVE-2024-46328, see:
# https://hawktesters.com/5519644d-246e-4924-b7c8-8fdf742117be/9461d352-c4f6-477f-a44e-b91ff71e6d84.pdf
#
# nb:
# - "test:test" is already included in another entry above and tested for all services
# - "admin:eaton" seems to be not specific to that VONETS vendor and thus is tested against all
#   services because it might be some kind of "branded" usage / device
# - While the advisory is only talking about HTTP the credentials might be used for other services
#   as well and thus tested against all
"root:vonets***pl:vonets:all,http,ssh,ftp",
"admin:eaton:vonets:all,http,ssh,ftp",

# nb:
# - Various Huawei ones from e.g.:
#   - https://forum.huawei.com/enterprise/en/huawei-ont-login-account-and-password/thread/667238610795118592-667213871523442688
#   - https://support.huawei.com/enterprise/en/knowledge/EKB1000080600
#   - Various additional known ones for Huawei Versatile Routing Platform (VRP) devices
# - "Epuser:userEp", "Eproot:adminEp" and "Epadmin:adminEp" haven't been added because these seems
#   to be only valid for the Web login and/or Telnet
# - It is not fully clear for which protocols all passwords are used and for now only SSH was specified
# - "root:admin" seems to be generic and is getting tested for all but ftp
# - "admin:admin" is already included separately further up
# - "telecomadmin:admintelecom" is also mentioned for Nokia devices on e.g.
#   https://setuprouter.com/router/nokia/passwords.htm but might only apply to the Web GUI. It was
#   still included below just to be sure...
"root:admin:huawei,various:all,http,ssh",
"root:adminHW:huawei:ssh",
"user:HuaweiUser:huawei:ssh",
"telecomadmin:admintelecom:huawei,nokia:ssh",
"admin:@HuaweiHgw:huawei:ssh",
"admin:admin@huawei.com:huawei:ssh",
"admin:Admin@huawei:huawei:ssh",
"admin:Admin@123:huawei:ssh",
"super:sp-admin:huawei:ssh",
"audit-admin:Admin@123:huawei:ssh",

# nb:
# - All the following are from / as listed on https://isc.sans.edu/diary/31360?n with some own
#   research involved
# - Add new credentials not included on the list above more up so that these entries are kept last
# - "vadmin" hasn't been added as the password will be random according to:
#   https://vitux.com/openlitespeed-debian/
# - "telecomadmin" is already covered in the Huawei part above
# - "telnet" isn't a supported protocol yet but still included in two credential pairs below to
#   support it once available
# - Password for user "chenzilong" unknown and thus it wasn't added below

# Polycom CX600 IP phones according to some online resources
"345gs5662d34:345gs5662d34:polycom:ssh",
"root:345gs5662d34:polycom:ssh",

# CVE-2020-29583
"zyfwp:PrOw!aN_fXp:zyxel:ssh",

# Youhua PT939G fiber router, see e.g.
# > https://blog.yeziruo.com/archives/108.html
# or from the SANS ISC diary for the "ve0RbANG" password:
# > used with the "YhtcAdmin" username for Youhua PT939G optical network termination equipment.
"yhtcAdmin:Cm1@YHfw:youhua:ssh,telnet",
"YhtcAdmin:ve0RbANG:youhua:ssh,telnet",
"Admin:1234:youhua:ssh,telnet",
"Admin:Telecom_1234:youhua:ssh,telnet",

# Dahua NVRs
"admin:7ujMko0admin:dahua:ssh,telnet",

# Routers using Realtek chipset
"root:a1sev5y7c39k:realtek:ssh",

# nb:
# - CVE-2017-16523: MitraStar GPT-2541GNAC (HGU) 1.00(VNJ0)b1 and DSL-100HN-T1 ES_113WJY0b16 devices
#   seems to have used "zyad1234:zyad1234" for SSH according to:
#   https://www.exploit-db.com/exploits/43061
# - The "zyad1234" password was also seen for the "supervisor" account on Zyxel devices but this
#   one was only referenced for Telnet connections and hasn't been added for SSH below
"zyad1234:zyad1234:mitrastar:ssh",
"supervisor:zyad1234:zyxel:telnet",

# V-SOL GPON OLT
# see e.g. https://www.vsolcn.com/blog/vsol-gpon-olt-basics-and-configuration.html
"admin:Xpon@Olt9417#:v-sol:ssh",

# CVE-2005-1379
# > The LAM runtime environment package (lam-runtime-7.0.6-2mdk) on Mandrake Linux installs the mpi user without a password
"mpi:<<none>>:mandrake:ssh",

# CVE-2009-3710
# > RioRey RIOS 4.6.6 and 4.7.0 uses an undocumented, hard-coded username (dbadmin) and password (sq!us3r) for an SSH tunnel
"dbadmin:sq!us3r:riorey:ssh",

# CVE-2016-1000245
# - For HangZhou XiongMai Technologies
# - https://securityledger.com/2016/10/shoddy-supply-chain-lurks-behind-mirai-botnet/ shows the credentials
# - While the text shows "typically telnet" SSH is checked as well on purpose as the CVE description
#   (extracted from some DWF project archives) is stating:
#  > Please note that this vulnerability affects a wide number of products and manufacturers that
#  > ship products based on the hardware and software shipped by HangZhou XiongMai Technologies.
"root:xc3511:xiongmai:ssh,telnet",

# - See e.g.:
#   - https://www.elasticsky.de/en/2018/02/change-brocade-fos-default-passwords/
#   - https://pierrekim.github.io/blog/2025-03-31-brocade-switches-10-vulnerabilities.html#default-weak-creds
# - User will be prompted to change the password on first login but the device might not be
#   configured yet or has been recently reset so it is checked here as well
# - Some online resources are also showing "fivranne":
#   https://www.experts-exchange.com/questions/25070077/factory-defaults-on-HP-Storagework-san-switch-2-32.html
#   and this was also included in the original version of this include so it has been kept here
"root:fibranne:brocade:ssh,telnet",
"root:fivranne:brocade:ssh,telnet",

# - CVE-2024-9643: Four-Faith routers
# - CVE-2023-32645: Yifan YF325 routers
# - Both CVEs are pointing to the same default credentials shown at: https://talosintelligence.com/vulnerability_reports/TALOS-2023-1752
"ffadmin:ffadminff:four-faith,yifan:http",

# From CVE-2024-27170, see https://pierrekim.github.io/blog/2024-06-27-toshiba-mfp-40-vulnerabilities.html#hardcoded-credentials-webdav
"EBX:toshiba:toshiba:http",

# Nokia SR Linux devices, see https://documentation.nokia.com/srlinux/24-7/books/config-basics/secur-access.html
# - Valid for at least FTP and SSH
# - The page indicates that these might be also valid for e.g. JSON-RPC
"linuxadmin:NokiaSrl1!:nokia:ssh,ftp",

# Mentioned on various resources like e.g.:
# - https://www.scribd.com/document/864896719/SRIO-Detection-1
# - https://www.scribd.com/document/586675492/Nokia-eNodeB-Ping-trace-M-U-C
# - https://pdfcoffee.com/sbts-troublshooting-document-pdf-free.html
#
# The following document indicates that this user is valid for SSH and FTP:
# https://www.synacktiv.com/sites/default/files/2023-02/Synacktiv-Nokia-BTS-AirScale-Asika-Multiple-Vulnerabilities.pdf
#
# Assumed to be valid for these products:
# - SBTS (Single RAN Base Transceiver Station)
# - eNodeB
"toor4nsn:oZPS0POrRieRtu:nokia:ssh,ftp",

# Mentioned on various resources like e.g.:
# - https://osmocom.org/projects/ericsson-rbs-6xxx/wiki/DUL_20_Configuration/13
# - https://danielrios.me/apuntes/2324ir5G/BBU6630.pdf (On page "Core sftp server settings" the protocols "FTP", "HTTPS" and "SSH/SFTP" are mentioned)
# - https://www.telecomhall.net/t/whats-is-default-username-password-for-a-ericsson-node/30084/2
#
# - Assumed to be valid for Ericsson Radio Base Stations (RBS)
# - Confirmed to be valid for Ericsson Baseband 6648 (SSH only)
"rbs:rbs:ericsson:ssh,ftp",

# Both mentioned on various resources like e.g.:
# - https://setuprouter.com/router/nokia/passwords.htm
# - https://shapath.com.np/til/til-ssh-telnet-into-nokia-g-2425-g-a/
#
# Second link includes the following below as well as the second credentials pair.
# > Default login for SSH, Telnet CLI, and Web GUI
"AdminGPON:ALC#FGU:nokia:ssh",
"userAdmin:userAdmin:nokia:ssh",

# GeoServer (https://docs.geoserver.org/main/en/user/gettingstarted/web-admin-quickstart/index.html#logging-in)
"admin:geoserver:geoserver:http"
);

uploaded_credentials = get_kb_list( "default_credentials/credentials" );
if( uploaded_credentials ) {

  uploaded_credentials_only = get_kb_item( "default_credentials/uploaded_credentials_only" );
  if( uploaded_credentials_only && uploaded_credentials_only == "yes" ) {
    credentials = uploaded_credentials;
  } else {
    credentials = make_list( uploaded_credentials, credentials );
  }
}

# @brief Returns a list of credentials from this include defined via the `credentials` list on top.
#
# @note This function is currently only used in a handful of VTs, namely:
#
# - common/pre2008/cisco_default_pw_ssh.nasl
# - common/pre2008/3com_switches.nasl
# - common/pre2008/Accelar_1200.nasl
# - common/pre2008/avaya_switches.nasl
# - common/pre2008/Allied_Telesyn_telnet.nasl
# - common/pre2008/cisco_default_pw_telnet.nasl
#
# Other Brute-Force VTs are NOT using this function (on purpose) as it doesn't make any sense to
# define a vendor for them as these have no knowledge (and should have no) on the vendor of the
# remote device they are running against.
#
# @param vendor An optional vendor string (e.g. "cisco") for which credentials should be returned /
#               only included.
#
# @return A list of credentials as described previously.
#
function default_credentials_get_list( vendor ) {

  local_var vendor;
  local_var _credential, clist;
  # nb: "credentials" is a global variable defined at the top

  if( ! vendor || isnull( vendor ) || vendor == "" )
    return credentials;

  foreach _credential( credentials ) {

    if( vendor >!< _credential )
      continue;

    if( typeof( clist ) == "undef") {
      clist = make_list( _credential );
    } else {
      clist = make_list( clist, _credential );
    }
  }
  return clist;
}
