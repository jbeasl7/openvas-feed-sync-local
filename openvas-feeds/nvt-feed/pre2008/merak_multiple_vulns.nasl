# SPDX-FileCopyrightText: 2004 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:icewarp:mail_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14379");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2004-1719", "CVE-2004-1720", "CVE-2004-1721", "CVE-2004-1722");
  script_name("Merak Webmail / IceWarp Web Mail < 7.5.2 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("gb_icewarp_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("icewarp/mailserver/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10966");
  script_xref(name:"OSVDB", value:"9037");
  script_xref(name:"OSVDB", value:"9038");
  script_xref(name:"OSVDB", value:"9039");
  script_xref(name:"OSVDB", value:"9040");
  script_xref(name:"OSVDB", value:"9041");
  script_xref(name:"OSVDB", value:"9042");
  script_xref(name:"OSVDB", value:"9043");
  script_xref(name:"OSVDB", value:"9044");
  script_xref(name:"OSVDB", value:"9045");

  script_tag(name:"summary", value:"Merak Webmail / IceWarp Web Mail is prone to multiple cross-site
  scripting (XSS), HTML and SQL injection (SQLi), and PHP source code disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Update to Merak Webmail / IceWarp Web Mail 7.5.2 or later.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

# nb: "install" variable in gb_icewarp_consolidation.nasl is currently "webmail"
if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/webmail/inc/function.php";

if (http_vuln_check(port: port, url: url, pattern: "function getusersession", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
