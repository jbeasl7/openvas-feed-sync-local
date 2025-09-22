# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807080");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2016-2038", "CVE-2016-2039", "CVE-2016-2040", "CVE-2016-2041",
                "CVE-2016-1927");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-02-23 10:17:05 +0530 (Tue, 23 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("phpMyAdmin Multiple Vulnerabilities -01 (Feb 2016)");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to obtain sensitive information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The recommended setting of the PHP configuration directive display_errors is
    set to on, which is against the recommendations given in the PHP manual
    for a production server.

  - The XSRF/CSRF token is generated with a weak algorithm using functions
    that do not return cryptographically secure values.

  - An insufficient validation of user supplied input via parameters
    table name, SET value, hostname header and search query.

  - The password suggestion functionality uses 'Math.random' function which does
    not provide cryptographically secure random numbers.

  - The 'libraries/common.inc.php' script does not use a constant-time algorithm
    for comparing CSRF tokens.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information about the server and to inject
  arbitrary web script or HTML, to bypass intended access restrictions and
  to guess passwords.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.0.x prior to 4.0.10.13,
  4.4.x prior to 4.4.15.3 and 4.5.x prior to 4.5.4");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 4.0.10.13 or
  4.4.15.3 or 4.5.4 or later or apply the patch from the linked references.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-4");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82075");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/81210");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82077");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82076");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-5");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-3");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-2");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-1");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_mandatory_keys("phpMyAdmin/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/setup/lib/common.inc.php';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"Fatal error.*PMA_fatalError.*common.inc.php"))
{
  report = http_report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}
