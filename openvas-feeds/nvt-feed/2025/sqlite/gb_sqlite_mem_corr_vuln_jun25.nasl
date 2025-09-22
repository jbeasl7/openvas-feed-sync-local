# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sqlite:sqlite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154981");
  script_version("2025-07-23T05:44:58+0000");
  script_tag(name:"last_modification", value:"2025-07-23 05:44:58 +0000 (Wed, 23 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-18 03:38:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-22 17:06:21 +0000 (Tue, 22 Jul 2025)");

  script_cve_id("CVE-2025-6965");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SQLite < 3.50.2 Memory Corruption Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The number of aggregate terms could exceed the number of
  columns available. This could lead to a memory corruption issue.");

  script_tag(name:"impact", value:"An attacker who can inject arbitrary SQL statements into an
  application might be able to cause an integer overflow resulting in read off the end of an
  array.");

  script_tag(name:"affected", value:"SQLite version 3.50.1 and prior.");

  script_tag(name:"solution", value:"Update to version 3.50.2 or later.");

  script_xref(name:"URL", value:"https://sqlite.org/releaselog/3_50_2.html");
  script_xref(name:"URL", value:"https://sqlite.org/cves.html");
  script_xref(name:"URL", value:"https://www.sqlite.org/src/info/5508b56fd24016c13981ec280ecdd833007c9d8dd595edb295b984c2b487b5c8");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.50.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.50.2", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
