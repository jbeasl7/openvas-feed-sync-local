# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mahara:mahara";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.155206");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-25 05:03:17 +0000 (Mon, 25 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-45133", "CVE-2022-45134");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mahara 21.10 < 21.10.6, 22.04 < 22.04.4, 22.10 < 22.10.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mahara_http_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"summary", value:"Mahara is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2022-45133: Unsafe deserialization of user input in skin import. A particularly structured
  XML file could cause code execution when being processed.

  - CVE-2022-45134: Unsafe deserialization of user input in skin import. A particularly structured
  XML file could cause code execution when being processed.");

  script_tag(name:"affected", value:"Mahara version 21.10 prior to 21.10.6, 22.04 prior to 22.04.4
  and 22.10 prior to 22.10.1.");

  script_tag(name:"solution", value:"Update to version 21.10.6, 22.04.4, 22.10.1 or later.");

  script_xref(name:"URL", value:"https://mahara.org/interaction/forum/topic.php?id=9353");

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

if (version_in_range_exclusive(version: version, test_version_lo: "21.10", test_version_up: "21.10.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.10.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "22.04", test_version_up: "22.04.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.04.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "22.10", test_version_up: "22.10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.10.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
