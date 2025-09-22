# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144365");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-08-07 01:41:19 +0000 (Fri, 07 Aug 2020)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-25 16:03:00 +0000 (Thu, 25 Feb 2021)");

  script_cve_id("CVE-2020-7068");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 7.2.33, 7.3 < 7.3.21, 7.4 < 7.4.9 DoS Vulnerability (Aug 2020) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to a denial of service vulnerability in the phar_parse_zipfile function.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The phar_parse_zipfile function had use-after-free vulnerability because of
  mishandling of the actual_alias variable.");

  script_tag(name:"affected", value:"PHP versions prior 7.2.33, 7.3 prior 7.3.21 and 7.4 prior to 7.4.9.");

  script_tag(name:"solution", value:"Update to version 7.2.33, 7.3.21, 7.4.9 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.2.33");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.3.21");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.4.9");

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

if (version_is_less(version: version, test_version: "7.2.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);

}

if (version_in_range(version: version, test_version: "7.3.0", test_version2: "7.3.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.4.0", test_version2: "7.4.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
