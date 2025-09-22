# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902016");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2010-0438");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Multiple SQLi Vulnerabilities (OSA-2010-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to multiple SQL
  injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to error in 'Kernel/System/Ticket.pm' in
  'OTRS-Core'. It fails to sufficiently sanitize user-supplied data before using it in SQL
  queries.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate SQL
  queries to read or modify records in the database, could also allow access to more administrator
  permissions.");

  script_tag(name:"affected", value:"OTRS versions 2.1.x prior to 2.1.9, 2.2.x prior to 2.2.9,
  2.3.x prior to 2.3.5 and 2.4.x prior to 2.4.7.");

  script_tag(name:"solution", value:"Update to version 2.1.9, 2.2.9, 2.3.5, 2.4.7 or later.");

  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2010-01-en/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38146");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2010-0438");

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

if (version_in_range(version: version, test_version: "2.1.0", test_version2: "2.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.2.0", test_version2: "2.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.3.0", test_version2: "2.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.4.0", test_version2: "2.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
