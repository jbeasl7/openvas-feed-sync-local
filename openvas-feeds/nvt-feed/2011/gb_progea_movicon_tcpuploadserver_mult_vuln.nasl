# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801969");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_cve_id("CVE-2011-2963");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Progea Movicon 'TCPUploadServer.exe' Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("find_service.nasl");
  script_require_ports(10651);

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17034/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46907");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-11-056-01.pdf");

  script_tag(name:"insight", value:"Multiple flaws are due to error in 'TCPUploadServer.exe', allows the
  attackers to data leakage, data manipulation or denial of service.");
  script_tag(name:"solution", value:"Upgrade to Progea Movicon 11.2 Build 1084 or later.");
  script_tag(name:"summary", value:"Progea Movicon is prone to multiple vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform unauthorised actions,
  obtain sensitive information and cause denial-of-service conditions.");
  script_tag(name:"affected", value:"Progea Movicon version 11.2 Build prior to 1084");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.progea.com/");
  exit(0);
}

port = 10651;

if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

data= "MovX7" + raw_string(0x00);

## Send the attack string
send(socket:soc, data:data);
rcv = recv(socket:soc, length:1024);

if("MovX7" >< rcv && "Service Pack" >< rcv){
  security_message(port);
}
