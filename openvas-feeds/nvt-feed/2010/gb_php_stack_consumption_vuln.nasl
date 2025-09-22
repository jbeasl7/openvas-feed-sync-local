# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801547");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2010-3709", "CVE-2010-3710");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.2.x < 5.2.15, 5.3.x < 5.3.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2010-3709: NULL pointer dereference vulnerability in 'ZipArchive::getArchiveComment'

  - CVE-2010-3710: Stack consumption vulnerability in the filter_var function when
  FILTER_VALIDATE_EMAIL mode is used while processing the long e-mail address string.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a
  denial of service (memory consumption and application crash) via a long e-mail address string.");

  script_tag(name:"affected", value:"PHP version 5.2.x through 5.2.14 and 5.3.x through 5.3.3.");

  script_tag(name:"solution", value:"Update to version 5.2.15, 5.3.4 or later.");

  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=52929");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=646684");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/514562/30/150/threaded");

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

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.14")) {
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
