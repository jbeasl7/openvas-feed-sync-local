# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113256");
  script_version("2024-02-13T05:06:26+0000");
  script_tag(name:"last_modification", value:"2024-02-13 05:06:26 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-08-29 11:16:18 +0200 (Wed, 29 Aug 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-26 01:11:00 +0000 (Fri, 26 Oct 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-15605");

  script_name("phpMyAdmin <= 4.8.2 XSS Vulnerability (PMASA-2018-5) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"phpMyAdmin is prone to an authenticated Cross-Site Scripting (XSS) Vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An authenticated attacker could trick a user into importing a specially crafted file,
  resulting in the attacker gaining control over the user's account.");
  script_tag(name:"affected", value:"phpMyAdmin through version 4.8.2.");
  script_tag(name:"solution", value:"Update to version 4.8.3.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2018-5/");

  exit(0);
}

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "4.8.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.8.3" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
