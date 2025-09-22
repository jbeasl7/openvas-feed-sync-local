# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103020");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"creation_date", value:"2011-01-10 13:28:19 +0100 (Mon, 10 Jan 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2010-4645");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.2.x < 5.2.17, 5.3.x < 5.3.5 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to the Floating-Point value that
  exist in zend_strtod function.");

  script_tag(name:"impact", value:"Successful attacks will cause applications written in PHP to
  hang, creating a denial of service condition.");

  script_tag(name:"affected", value:"PHP versions 5.2.x prior to 5.2.17 and 5.3.x prior to
  5.3.5.");

  script_tag(name:"solution", value:"Update to version 5.2.17, 5.3.5 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20111122101850/http://www.securityfocus.com/bid/45668");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=53632");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc/?view=revision&revision=307119");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=307095");
  script_xref(name:"URL", value:"http://www.exploringbinary.com/php-hangs-on-numeric-value-2-2250738585072011e-308/");

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

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3.0", test_version2: "5.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
