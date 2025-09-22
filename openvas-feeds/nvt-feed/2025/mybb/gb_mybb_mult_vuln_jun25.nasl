# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127894");
  script_version("2025-06-06T05:41:39+0000");
  script_tag(name:"last_modification", value:"2025-06-06 05:41:39 +0000 (Fri, 06 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-05 07:00:46 +0000 (Thu, 05 Jun 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2025-48940", "CVE-2025-48941");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB < 1.8.39 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_http_detect.nasl");
  script_mandatory_keys("mybb/detected");

  script_tag(name:"summary", value:"MyBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-48940: The upgrade component does not validate user input properly, which allows
  attackers to perform local file inclusion (LFI) via specially crafted parameter value.

  - CVE-2025-48941: The search component does not validate permissions correctly, which allows
  attackers to determine the existence of hidden (draft, unapproved, or soft-deleted) threads
  containing specified text in the title.");

  script_tag(name:"affected", value:"MyBB prior to version 1.8.39.");

  script_tag(name:"solution", value:"Update to version 1.8.39 or later.");

  script_xref(name:"URL", value:"https://github.com/mybb/mybb/security/advisories/GHSA-q4jv-xwjx-37cp");
  script_xref(name:"URL", value:"https://github.com/mybb/mybb/security/advisories/GHSA-f847-57xc-ffwr");

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

if (version_is_less(version: version, test_version: "1.8.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
