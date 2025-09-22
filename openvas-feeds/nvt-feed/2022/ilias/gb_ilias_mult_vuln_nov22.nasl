# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148964");
  script_version("2023-11-22T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-11-22 05:05:24 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"creation_date", value:"2022-11-28 10:03:33 +0000 (Mon, 28 Nov 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-09 17:15:00 +0000 (Fri, 09 Dec 2022)");

  script_cve_id("CVE-2022-45915", "CVE-2022-45916", "CVE-2022-45917", "CVE-2022-45918");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 6.20, 7.x < 7.16 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_http_detect.nasl");
  script_mandatory_keys("ilias/detected");

  script_tag(name:"summary", value:"ILIAS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-45915: Multiple OS command injections

  - CVE-2022-45916: Multiple cross-site scriptings (XSS)

  - CVE-2022-45917: Open redirect

  - CVE-2022-45918: Local file inclusion (LFI)");

  script_tag(name:"affected", value:"ILIAS prior to version 6.20 and version 7.x prior to 7.16.");

  script_tag(name:"solution", value:"Update to version 6.20, 7.16 or later.");

  script_xref(name:"URL", value:"https://docu.ilias.de/goto_docu_pg_140768_35.html");
  script_xref(name:"URL", value:"https://docu.ilias.de/goto_docu_pg_140770_35.html");
  script_xref(name:"URL", value:"https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-ilias-elearning-platform/");

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

if (version_is_less(version: version, test_version: "6.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

