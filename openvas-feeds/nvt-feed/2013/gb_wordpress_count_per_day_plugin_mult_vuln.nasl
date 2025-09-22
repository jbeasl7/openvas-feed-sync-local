# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803430");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-03-06 11:34:32 +0530 (Wed, 06 Mar 2013)");
  script_name("WordPress Count per Day Plugin Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Mar/43");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Mar/48");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
HTML or web script in a user's browser session in context of an affected site,
cause denial of service, and discloses the software installation path results
in a loss of confidentiality.");
  script_tag(name:"affected", value:"WordPress Count per Day plugin <= 3.2.5");
  script_tag(name:"insight", value:"- Malicious input passed via 'daytoshow' parameter to /wp-content
/wp-admin/index.php script is not properly sanitised before being returned to
the user.

  - Malicious input passed via POST parameters to wordpress/wp-content/plugins
/count-per-day/notes.php script is not properly sanitised before being
returned to the user.

  - Malformed GET request to ajax.php, counter-core.php, counter-options.php,
counter.php, massbots.php, and userperspan.php scripts.");
  script_tag(name:"solution", value:"Update to version 3.2.6 or later.");
  script_tag(name:"summary", value:"The WordPress plugin 'Count per Day' is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/count-per-day");
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

url = dir + '/wp-content/plugins/count-per-day/ajax.php';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"<b>Notice</b>:  Undefined index: f in.*ajax.php"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
