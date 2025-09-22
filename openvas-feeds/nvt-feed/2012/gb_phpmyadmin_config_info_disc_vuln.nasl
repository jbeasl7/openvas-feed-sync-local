# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802430");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2012-1902");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-04-17 12:56:58 +0530 (Tue, 17 Apr 2012)");
  script_name("phpMyAdmin Information Disclosure Vulnerability (PMASA-2012-2) - Active Check");
  script_xref(name:"URL", value:"http://english.securitylab.ru/nvd/422861.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52858");
  script_xref(name:"URL", value:"http://www.auscert.org.au/render.html?it=15653");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=809146");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2012-2.php");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"affected", value:"phpMyAdmin version 3.4.10.2 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an input validation error in
  'show_config_errors.php'. When a configuration file does not exist, allows remote attackers to
  obtain sensitive information via a direct request.");

  script_tag(name:"solution", value:"Update to version 3.4.10.2 or later.");

  script_tag(name:"summary", value:"phpMyAdmin is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution_type", value:"VendorFix");

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

url = dir + "/show_config_errors.php";

if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:"Failed opening required.*\show_config_errors\.php")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
