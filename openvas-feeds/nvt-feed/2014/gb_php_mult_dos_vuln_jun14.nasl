# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804639");
  script_version("2025-05-02T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-05-02 05:40:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"creation_date", value:"2014-06-16 10:22:50 +0530 (Mon, 16 Jun 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2014-0237", "CVE-2014-0238");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.x < 5.4.29, 5.5.x < 5.5.13 Multiple DoS Vulnerabilities (Jun 2014)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-0237: Infinite loop within the 'unpack_summary_info' function in src/cdf.c script.

  - CVE-2014-0238: An error within the 'cdf_read_property_info' function in src/cdf.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  denial of service attacks.");

  script_tag(name:"affected", value:"PHP version 5.x before 5.4.29 and 5.5.x before 5.5.13.");

  script_tag(name:"solution", value:"Update to version 5.4.29, 5.5.13 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67759");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67765");
  script_xref(name:"URL", value:"http://secunia.com/advisories/58804");
  script_xref(name:"URL", value:"https://www.hkcert.org/my_url/en/alert/14060401");

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

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.4.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.5.0", test_version2: "5.5.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
