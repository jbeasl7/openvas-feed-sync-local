# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sqlite:sqlite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155338");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-16 04:32:53 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:C/A:P");

  script_cve_id("CVE-2025-7709");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SQLite < 3.50.3 Integer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to an integer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow exists in the FTS5 extension. It occurs
  when the size of an array of tombstone pointers is calculated and truncated into a 32-bit
  integer. A pointer to partially controlled data can then be written out of bounds.");

  script_tag(name:"affected", value:"SQLite prior to version 3.50.3.");

  script_tag(name:"solution", value:"Update to version 3.50.3 or later.");

  script_xref(name:"URL", value:"https://github.com/google/security-research/security/advisories/GHSA-v2c8-vqqp-hv3g");
  script_xref(name:"URL", value:"https://sqlite.org/src/info/63595b74956a9391");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.50.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.50.3", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
