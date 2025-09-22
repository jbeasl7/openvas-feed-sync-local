# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131013");
  script_version("2025-05-02T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-05-02 05:40:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"creation_date", value:"2024-08-21 13:23:51 +0000 (Wed, 21 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-01 16:03:08 +0000 (Thu, 01 May 2025)");

  script_cve_id("CVE-2024-43425", "CVE-2024-43426", "CVE-2024-43427", "CVE-2024-43428",
                "CVE-2024-43429", "CVE-2024-43431", "CVE-2024-43432", "CVE-2024-43434",
                "CVE-2024-43436", "CVE-2024-43435", "CVE-2024-43437", "CVE-2024-43438",
                "CVE-2024-43439", "CVE-2024-43440");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 4.1.12, 4.2.x < 4.2.9, 4.3.x < 4.3.6, 4.4.x < 4.4.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-43425 / MSA-24-0026: RCE via calculated question types

  - CVE-2024-43426 / MSA-24-0027: Arbitrary file read risk through pdfTeX

  - CVE-2024-43427 / MSA-24-0028: Admin presets export tool includes some secrets that should not
  be exported.

  - CVE-2024-43428 / MSA-24-0029: Cache poisoning via injection into storage

  - CVE-2024-43429 / MSA-24-0030: User information visibility control issues in gradebook reports

  - CVE-2024-43431 / MSA-24-0032: IDOR in badges allows deletion of arbitrary badges

  - CVE-2024-43432 / MSA-24-0033: Authorization headers are preserved between 'emulated redirects'

  - CVE-2024-43434 / MSA-24-0035: CSRF risk in Feedback non-respondents report

  - CVE-2024-43436 / MSA-24-0036: It's possible to create global glossary without being admin

  - CVE-2024-43435 / MSA-24-0037: Site administration SQL injection via XMLDB editor

  - CVE-2024-43437 / MSA-24-0038: XSS risk when restoring malicious course backup file.

  - CVE-2024-43438 / MSA-24-0039: IDOR in Feedback non-respondents report allows messaging
  arbitrary site users.

  - CVE-2024-43439 / MSA-24-0040: Reflected XSS via H5P error message

  - CVE-2024-43440 / MSA-24-0041: LFI vulnerability when restoring malformed block backups.");

  script_tag(name:"affected", value:"Moodle version prior to 4.1.12, 4.2.x prior to 4.2.9,
  4.3.x prior to 4.3.6 and 4.4.x prior to 4.4.2.");

  script_tag(name:"solution", value:"Update to version 4.1.12, 4.2.9, 4.3.6, 4.4.2 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461193");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461194");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461195");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461196");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461197");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461199");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461200");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461203");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461205");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461206");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461207");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461208");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461209");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=461210");

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

if (version_is_less(version: version, test_version: "4.1.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2.0", test_version_up: "4.2.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3.0", test_version_up: "4.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4.0", test_version_up: "4.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
