# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127443");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2023-05-25 07:00:52 +0000 (Thu, 25 May 2023)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-02 12:57:00 +0000 (Fri, 02 Jun 2023)");

  script_cve_id("CVE-2023-32318");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server 25.0.2 < 25.0.6, 26.0.x < 26.0.1 Insufficient Session Expiration Vulnerability (GHSA-q8c4-chpj-6v38)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an insufficient session expiration
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A regression in the session handling between Nextcloud Server
  and the Nextcloud Text app prevents a correct destruction of the session on logout if cookies
  are not cleared manually.");

  script_tag(name:"affected", value:"Nextcloud Server version 25.0.2 prior to 25.0.6,
  26.0.x prior to 26.0.1.");

  script_tag(name:"solution", value:"Update to version 25.0.6, 26.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-q8c4-chpj-6v38");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "25.0.2", test_version_up: "25.0.6" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "25.0.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "26.0.0", test_version_up: "26.0.1" ) ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "26.0.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
