# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100399");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2009-3563");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)");
  script_name("NTP mode 7 MODE_PRIVATE Packet Remote Denial of Service Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("ntp_open.nasl");
  script_require_udp_ports("Services/udp/ntp", 123);
  script_mandatory_keys("ntp/remote/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37255");
  script_xref(name:"URL", value:"https://support.ntp.org/bugs/show_bug.cgi?id=1331");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/568372");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"NTP.org's ntpd is prone to a remote denial-of-service vulnerability because it
  fails to properly handle certain incoming network packets.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause the application to consume
  excessive CPU resources and fill disk space with log messages.");

  script_tag(name:"vuldetect", value:"Send a NTP mode 7 request and check the response.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:123, ipproto:"udp", proto:"ntp");

soc = open_sock_udp(port);
if(!soc)
  exit(0);

data = raw_string(0x97, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00);
send(socket:soc, data:data);
r = recv(socket:soc, length:8);
close(soc);

if(!r)
  exit(0);

if(hexstr(r) == "9700000030000000") {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);
