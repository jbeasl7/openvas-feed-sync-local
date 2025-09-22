# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127333");
  script_version("2025-09-01T05:39:44+0000");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"creation_date", value:"2023-02-10 12:27:44 +0000 (Fri, 10 Feb 2023)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-14 15:17:00 +0000 (Tue, 14 Mar 2023)");

  script_cve_id("CVE-2022-41862");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 12.x < 12.14, 13.x < 13.10, 14.x < 14.7, 15.x < 15.2 Information Disclosure Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A modified, unauthenticated server or an unauthenticated
  man-in-the-middle can send an unterminated string during the establishment of Kerberos transport
  encryption. When a libpq client application has a Kerberos credential cache and doesn't
  explicitly disable option gssencmode, a server can cause libpq to over-read and report an error
  message containing uninitialized bytes from and following its receive buffer. If libpq's caller
  somehow makes that message accessible to the attacker, this achieves a disclosure of the
  over-read bytes.");

  script_tag(name:"affected", value:"PostgreSQL versions 12.x prior to 12.14, 13.x prior to 13.10,
  14.x prior to 14.7 and 15.x prior to 15.2.");

  script_tag(name:"solution", value:"Update to version 12.14, 13.10, 14.7, 15.2 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-152-147-1310-1214-and-1119-released-2592/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2022-41862/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "12.0", test_version_up: "12.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.14", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "13.0", test_version_up: "13.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "13.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "14.0", test_version_up: "14.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "14.7", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "15.0", test_version_up: "15.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "15.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
