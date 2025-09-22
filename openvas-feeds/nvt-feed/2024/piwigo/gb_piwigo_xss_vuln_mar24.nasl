# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:piwigo:piwigo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126648");
  script_version("2024-03-19T15:34:11+0000");
  script_tag(name:"last_modification", value:"2024-03-19 15:34:11 +0000 (Tue, 19 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-14 09:51:16 +0000 (Thu, 14 Mar 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2024-28662");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo < 14.3.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A cross site scripting (XSS) because of missing sanitization in
  create_tag in admin/include/functions.php.");

  script_tag(name:"affected", value:"Piwigo prior to version 14.3.0.");

  script_tag(name:"solution", value:"Update to version 14.3.0 or later.");

  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/compare/14.2.0...14.3.0");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/security/advisories/GHSA-8g2g-6f2c-6h7j");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/security/advisories/GHSA-7379-w44f-mfw4");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/commit/5069610aaeb1da6d96d389651a5ba9b38690c580");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "14.3.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "14.3.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
