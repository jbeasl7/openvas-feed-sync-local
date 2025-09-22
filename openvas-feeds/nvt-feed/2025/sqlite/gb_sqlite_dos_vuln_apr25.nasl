# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sqlite:sqlite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128119");
  script_version("2025-06-19T05:40:14+0000");
  script_tag(name:"last_modification", value:"2025-06-19 05:40:14 +0000 (Thu, 19 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-04-14 12:28:38 +0000 (Mon, 14 Apr 2025)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2025-29088");

  script_name("SQLite <= 3.49.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain argument values to sqlite3_db_config (in the C-language
  API) can cause a denial-of-service (DoS) (application crash). An sz*nBig multiplication is not
  cast to a 64-bit integer, and consequently some memory allocations may be incorrect.");

  script_tag(name:"affected", value:"SQLite version 3.49.0 and prior.");

  script_tag(name:"solution", value:"Update to version 3.49.1 or later.");

  script_xref(name:"URL", value:"https://github.com/sqlite/sqlite/commit/56d2fd008b108109f489339f5fd55212bb50afd4");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "3.49.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.49.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
