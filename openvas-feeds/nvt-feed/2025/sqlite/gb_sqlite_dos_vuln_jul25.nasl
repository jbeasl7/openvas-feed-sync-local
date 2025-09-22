# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sqlite:sqlite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128176");
  script_version("2025-08-13T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-08-13 05:40:47 +0000 (Wed, 13 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-11 12:28:38 +0000 (Mon, 11 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-11 19:11:30 +0000 (Mon, 11 Aug 2025)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2025-7458");

  script_name("SQLite 3.39.2 - 3.41.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow in the sqlite3KeyInfoFromExprList function
  in SQLite versions 3.39.2 through 3.41.1 allows an attacker with the ability to execute arbitrary
  SQL statements to cause a denial of service or disclose sensitive information from process memory
  via a crafted SELECT statement with a large number of expressions in the ORDER BY clause.");

  script_tag(name:"affected", value:"SQLite version 3.39.2 through 3.41.1.");

  script_tag(name:"solution", value:"Update to version 3.41.2 or later.");

  script_xref(name:"URL", value:"https://sqlite.org/forum/forumpost/16ce2bb7a639e29b");
  script_xref(name:"URL", value:"https://sqlite.org/src/info/12ad822d9b827777");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "3.39.2", test_version_up: "3.41.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.41.2", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
