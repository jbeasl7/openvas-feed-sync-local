# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154053");
  script_version("2025-08-07T05:44:51+0000");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-02-20 04:50:29 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-06 23:57:20 +0000 (Wed, 06 Aug 2025)");

  script_cve_id("CVE-2024-38999", "CVE-2025-26525", "CVE-2025-26526", "CVE-2025-26527",
                "CVE-2025-26528", "CVE-2025-26529", "CVE-2025-26531", "CVE-2025-26532",
                "CVE-2025-26533");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle Multiple Vulnerabilities (Feb 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-26525 / MSA-25-0001: Arbitrary file read risk through pdfTeX

  - CVE-2025-26526 / MSA-25-0002: Feedback response viewing and deletions did not respect Separate
  Groups mode

  - CVE-2025-26527 / MSA-25-0003: Non-searchable tags can still be discovered on the tag search
  page and in the tags block

  - CVE-2025-26528 / MSA-25-0004: Stored XSS in ddimageortext question type

  - CVE-2025-26529 / MSA-25-0005: Stored XSS risk in admin live log

  - CVE-2024-38999 / MSA-25-0007: Vulnerability in RequireJS

  - CVE-2025-26531 / MSA-25-0008: IDOR in badges allows disabling of arbitrary badges

  - CVE-2025-26532 / MSA-25-0009: Teachers can evade trusttext config when restoring glossary
  entries

  - CVE-2025-26533 / MSA-25-0010: SQL injection risk in course search module list filter");

  script_tag(name:"affected", value:"Moodle version 4.1.15, 4.3 through 4.3.9, 4.4 through 4.4.5
  and 4.5 through 4.5.1.");

  script_tag(name:"solution", value:"Update to version 4.1.16, 4.3.10, 4.4.6, 4.5.2 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=466141");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=466142");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=466143");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=466144");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=466145");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=466147");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=466148");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=466149");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=466150");

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

if (version_is_less(version: version, test_version: "4.1.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.3.0", test_version_up: "4.3.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.4.0", test_version_up: "4.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.5.0", test_version_up: "4.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
