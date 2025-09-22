# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112538");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2019-03-19 09:51:12 +0100 (Tue, 19 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-18 14:12:00 +0000 (Mon, 18 Mar 2019)");

  script_cve_id("CVE-2018-20800");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 5.x <= 5.0.31, 6.x <= 6.0.13 Data Loss Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"OTRS is prone to a data loss vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Users updating to OTRS 6.0.13 (also patchlevel updates) or
  5.0.31 (only major updates) will experience data loss in their agent preferences table.");

  script_tag(name:"affected", value:"OTRS versions 5.x through 5.0.31 and 6.x through 6.0.13.");

  script_tag(name:"solution", value:"Update to version 5.0.32, 6.0.14 or later.


  Note: If the system has been affected by the data loss, users can restore the user_preferences
  table from their backup and delete the OTRS cache via otrs/bin/otrs.Console.pl
  Maint::Delete::Cache. If the LDAP Sync module is used, it is sufficient to log in to the system
  again.");

  script_xref(name:"URL", value:"https://community.otrs.com/security-advisory-2018-10-security-update-for-otrs-framework/");

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

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
