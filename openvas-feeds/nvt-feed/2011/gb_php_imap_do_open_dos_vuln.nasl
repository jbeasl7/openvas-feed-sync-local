# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801583");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2011-01-31 05:37:34 +0100 (Mon, 31 Jan 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2010-4150");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 'ext/imap/php_imap.c' Use After Free DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error in 'imap_do_open' function in the IMAP extension
  'ext/imap/php_imap.c' may lead to denial of service.");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to crash
  the affected application, denying service to legitimate users.");

  script_tag(name:"affected", value:"PHP version 5.2 before 5.2.15 and 5.3 before 5.3.4");

  script_tag(name:"solution", value:"Update to PHP 5.2.15 or 5.3.4");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/63390");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44980");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=305032");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "5.2", test_version2: "5.2.14") ||
    version_in_range(version: version, test_version: "5.3", test_version2: "5.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.15 / 5.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
