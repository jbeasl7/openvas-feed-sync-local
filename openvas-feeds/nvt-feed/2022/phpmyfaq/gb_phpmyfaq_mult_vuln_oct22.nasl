# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127242");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2022-11-03 11:48:56 +0200 (Thu, 03 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-31 20:10:00 +0000 (Mon, 31 Oct 2022)");

  script_cve_id("CVE-2022-3754", "CVE-2022-3765", "CVE-2022-3766");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 3.1.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyfaq_http_detect.nasl");
  script_mandatory_keys("phpmyfaq/detected");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-3754: When users change password to a too simple password, attacker can easily guess
  user password and access account.

  - CVE-2022-3765: An malicious attacker can inject JavaScript code, steal cookie, deface website.

  - CVE-2022-3766: An malicious attacker can inject JavaScript code, steal cookie, deface
  website.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.1.8.");

  script_tag(name:"solution", value:"Update to version 3.1.8 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/f4711d7f-1368-48ab-9bef-45f32e356c47/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/613143a1-8e51-449a-b214-12458308835d/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/d9666520-4ff5-43bb-aacf-50c8e5570983/");

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

if (version_is_less(version: version, test_version: "3.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
