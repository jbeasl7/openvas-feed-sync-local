# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127937");
  script_version("2025-07-23T05:44:58+0000");
  script_tag(name:"last_modification", value:"2025-07-23 05:44:58 +0000 (Wed, 23 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-18 10:00:20 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2025-46337", "CVE-2025-49513", "CVE-2025-49514", "CVE-2025-49515",
                "CVE-2025-49516", "CVE-2025-49517", "CVE-2025-49518");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle Multiple Vulnerabilities (MSA-25-0031, MSA-25-0030, MSA-25-0032, MSA-25-0033, MSA-25-0034, MSA-25-0035, MSA-25-0036)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-46337 / MSA-25-0031: The upstream ADOdb library contained an SQL injection risk in the
  pg_insert_id() method

  - CVE-2025-49513 / MSA-25-0030: Password can be revealed in login page after log out due to
  caching

  - CVE-2025-49514 / MSA-25-0032: A DNS rebind risk in the way cURL requests were handled could
  result in an SSRF risk, due to the possibility of cURL blocked hosts / allowed ports site
  configurations being bypassed.

  - CVE-2025-49515 / MSA-25-0033: Insufficient state and capability checks resulted in some details
  of hidden courses (such as course name, description and teachers) being available to users who
  did not have permission to access them.

  - CVE-2025-49516 / MSA-25-0034: The 'move up' and 'move down' actions in backpack management for
  badges did not include the necessary token to prevent a CSRF risk.

  - CVE-2025-49517 / MSA-25-0035: Insufficient authorisation checks could result in users being
  able to view BigBlueButton recordings they did not have permission to access.

  - CVE-2025-49518 / MSA-25-0036: IDOR allows fetching of recently accessed courses for other users
  via web service");

  script_tag(name:"affected", value:"Moodle versions through 4.1.18, 4.4 through 4.4.8, 4.5 through
  4.5.4 and 5.0.");

  script_tag(name:"solution", value:"Update to version 4.1.19, 4.4.9, 4.5.5, 5.0.1 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=468502");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=468501");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=468503");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=468504");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=468505");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=468506");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=468507");

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


if (version_is_less_equal(version: version, test_version: "4.1.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4.0", test_version2: "4.4.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5.0", test_version2: "4.5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
