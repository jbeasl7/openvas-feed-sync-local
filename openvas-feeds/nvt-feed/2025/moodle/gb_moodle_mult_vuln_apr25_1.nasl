# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127865");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-24 07:06:20 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2024-40446", "CVE-2025-3635", "CVE-2025-3636", "CVE-2025-3637",
                "CVE-2025-3638", "CVE-2025-3640", "CVE-2025-3641", "CVE-2025-3642",
                "CVE-2025-3643", "CVE-2025-3644", "CVE-2025-3645", "CVE-2025-3647");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle Multiple Vulnerabilities (MSA-25-0013, MSA-25-0018, MSA-25-0019, MSA-25-0020, MSA-25-0021, MSA-25-0022, MSA-25-0023, MSA-25-0024, MSA-25-0025, MSA-25-0026, MSA-25-0027, MSA-25-0028)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-40446 / MSA-25-0013: Remote code execution risk via MimeTeX command (upstream)

  - CVE-2025-3635 / MSA-25-0018: CSRF risk in user tours manager allows tour duplication

  - CVE-2025-3636 / MSA-25-0019: IDOR in RSS block allows access to additional RSS feeds

  - CVE-2025-3637 / MSA-25-0020: mod_data edit/delete pages pass CSRF token in GET parameter

  - CVE-2025-3638 / MSA-25-0021: CSRF risk in Brickfield tool's analysis request action

  - CVE-2025-3640 / MSA-25-0022:  IDOR in web service allows users enrolled in a course to access
  some details of other users

  - CVE-2025-3641 / MSA-25-0023: Authenticated remote code execution risk in the Moodle LMS Dropbox
  repository

  - CVE-2025-3642 / MSA-25-0024: Authenticated remote code execution risk in the Moodle LMS EQUELLA
  repository

  - CVE-2025-3643 / MSA-25-0025: Reflected XSS risk in policy tool

  - CVE-2025-3644 / MSA-25-0026: AJAX section delete does not respect course_can_delete_section()

  - CVE-2025-3645 / MSA-25-0027: IDOR in messaging web service allows access to some user details

  - CVE-2025-3647 / MSA-25-0028: IDOR when accessing the cohorts report");

  script_tag(name:"affected", value:"Moodle versions through 4.1.17, 4.3 through 4.3.11, 4.4
  through 4.4.7 and 4.5 through 4.5.3.");

  script_tag(name:"solution", value:"Update to version 4.1.18, 4.3.12, 4.4.8, 4.5.4 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467592");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467597");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467598");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467599");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467600");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467601");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467602");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467603");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467604");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467605");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467606");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=467607");

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


if (version_is_less_equal(version: version, test_version: "4.1.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "4.3.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4.0", test_version2: "4.4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5.0", test_version2: "4.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
