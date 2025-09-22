# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opencart:opencart";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126419");
  script_version("2024-07-12T15:38:44+0000");
  script_tag(name:"last_modification", value:"2024-07-12 15:38:44 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"creation_date", value:"2023-06-26 21:10:42 +0000 (Mon, 26 Jun 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-27 20:21:00 +0000 (Tue, 27 Jun 2023)");

  script_cve_id("CVE-2020-20491");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenCart 2.2.0 < 3.0.3.6 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_opencart_http_detect.nasl");
  script_mandatory_keys("opencart/detected");

  script_tag(name:"summary", value:"OpenCart is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An SQL injection caused by inappropriate user input filtering
  in OpenBay extension.");

  script_tag(name:"affected", value:"OpenCart versions 2.2.0 prior to 3.0.3.6.");

  script_tag(name:"solution", value:"Update to version 3.0.3.6 or later.");

  script_xref(name:"URL", value:"https://github.com/opencart/opencart/releases/tag/3.0.3.6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "2.2.0", test_version_up: "3.0.3.6" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.3.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
