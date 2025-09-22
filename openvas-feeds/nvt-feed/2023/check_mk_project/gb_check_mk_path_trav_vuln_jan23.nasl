# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:checkmk:checkmk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127296");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2023-01-10 08:01:26 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-12 21:23:00 +0000 (Thu, 12 Jan 2023)");

  script_cve_id("CVE-2022-4884");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk 2.0.x < 2.0.0p33, 2.1.x < 2.1.0p19 Path Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_checkmk_server_http_detect.nasl");
  script_mandatory_keys("checkmk/server/detected");

  script_tag(name:"summary", value:"Checkmk is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated user with admin rights is able to upload a
  malicious MKP leading to a file creation with an attacker controlled path.");

  script_tag(name:"affected", value:"Checkmk versions 2.0.x prior to 2.0.0p33 and 2.1.x
  prior to 2.1.0p19.");

  script_tag(name:"solution", value:"Update to version 2.0.0p33, 2.1.0p19 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/15065");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "2.0.0", test_version_up: "2.0.0p33" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0p33", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.1.0", test_version_up: "2.1.0p19" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.0p19", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
