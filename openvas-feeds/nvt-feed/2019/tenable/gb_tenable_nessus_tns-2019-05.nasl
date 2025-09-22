# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112632");
  script_version("2023-11-17T16:10:13+0000");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-06-26 15:43:12 +0200 (Wed, 26 Jun 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-3974");

  script_name("Tenable Nessus <= 8.5.2 File Overwrite Vulnerability (TNS-2019-05)");

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_tenable_nessus_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("tenable/nessus/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Tenable Nessus on Windows is prone to an arbitrary file overwrite
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An authenticated, remote attacker could potentially exploit this
  vulnerability to create a denial of service condition.");

  script_tag(name:"affected", value:"Tenable Nessus through version 8.5.2.");

  script_tag(name:"solution", value:"Update to version 8.6.0 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2019-05");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"8.6.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.6.0", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
