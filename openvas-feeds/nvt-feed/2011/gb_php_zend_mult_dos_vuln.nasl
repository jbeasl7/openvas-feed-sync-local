# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801586");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-4697", "CVE-2010-4698");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.2.15, 5.3.x < 5.3.4 DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2010-4697: An use-after-free error in the 'Zend' engine, which allows remote attackers to
  cause a denial of service.

  - CVE-2010-4698: A stack-based buffer overflow in the 'GD' extension, which allows attackers to
  cause a denial of service.");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to crash
  the affected application, denying service to legitimate users.");

  script_tag(name:"affected", value:"PHP version prior to 5.2.15 and 5.3.x prior to 5.3.4.");

  script_tag(name:"solution", value:"Update to version 5.2.15, 5.3.4 or later.");

  script_xref(name:"URL", value:"http://bugs.php.net/52879");
  script_xref(name:"URL", value:"http://bugs.php.net/53492");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"https://web.archive.org/web/20120527082603/http://www.securityfocus.com/bid/45952");
  script_xref(name:"URL", value:"https://web.archive.org/web/20140615002045/http://www.securityfocus.com/bid/45338");

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

if (version_is_less(version: version, test_version: "5.2.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3.0", test_version2: "5.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
