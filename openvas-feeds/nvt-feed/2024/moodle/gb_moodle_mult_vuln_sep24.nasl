# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131040");
  script_version("2024-09-13T15:40:36+0000");
  script_tag(name:"last_modification", value:"2024-09-13 15:40:36 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-11 13:20:02 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:N");

  script_cve_id("CVE-2024-45689", "CVE-2024-45690", "CVE-2024-45691");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 4.1.13, 4.2.x < 4.2.10, 4.3.x < 4.3.7, 4.4.x < 4.4.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-45689 / MMSA-24-0042: Unprotected access to sensitive information via dynamic tables

  - CVE-2024-45690 / MMSA-24-0043: Insecure object direct reference (IDOR) when deleting OAuth2
  linked accounts

  - CVE-2024-45691 / MMSA-24-0044: When restricting access to a 'Lesson activity' with a password,
  some passwords could be bypassed due to a loose comparison in the password checking logic.");

  script_tag(name:"affected", value:"Moodle version prior to 4.1.13, 4.2.x prior to 4.2.10,
  4.3.x prior to 4.3.7 and 4.4.x prior to 4.4.3.");

  script_tag(name:"solution", value:"Update to version 4.1.13, 4.2.10, 4.3.7, 4.4.3 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461894");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461895");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461897");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.1.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2.0", test_version_up: "4.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3.0", test_version_up: "4.3.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4.0", test_version_up: "4.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
