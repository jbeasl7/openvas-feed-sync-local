# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807078");
  script_version("2025-09-09T14:09:45+0000");
  script_cve_id("CVE-2016-2044", "CVE-2016-2045");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-17 19:37:00 +0000 (Wed, 17 Aug 2016)");
  script_tag(name:"creation_date", value:"2016-02-22 19:19:14 +0530 (Mon, 22 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("phpMyAdmin Multiple Vulnerabilities (PMASA-2016-8, PMASA-2016-9) - Active Check");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to obtain sensitive information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - recommended setting of the PHP configuration directive display_errors is
    set to on, which is against the recommendations given in the PHP manual
    for a production server.

  - Insufficient validation of user supplied input via SQL query in the
    SQL editor");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information about the server and to inject
  arbitrary web script or HTML.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.5.x prior to 4.5.4.");

  script_tag(name:"solution", value:"Update to version 4.5.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-8");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-9");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82104");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82100");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_mandatory_keys("phpmyadmin/http/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/libraries/sql-parser/autoload.php";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"Fatal error.*autoload.php")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
