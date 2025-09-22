# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128115");
  script_version("2025-05-14T05:40:11+0000");
  script_tag(name:"last_modification", value:"2025-05-14 05:40:11 +0000 (Wed, 14 May 2025)");
  script_tag(name:"creation_date", value:"2025-04-01 12:10:52 +0000 (Tue, 01 Apr 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 13:34:02 +0000 (Tue, 13 May 2025)");

  script_cve_id("CVE-2025-29926");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 5.4-rc-1 < 15.10.15, 16.x < 16.4.6, 16.5.x < 16.10.0 Improper Authorization Vulnerability (GHSA-gfp2-6qhm-7x43)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to an improper authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability in WikiManager REST API allows any user to
  exploit the WikiManager REST API to create a new wiki, where the user could become an
  administrator and so performs other attacks on the farm.");

  script_tag(name:"affected", value:"XWiki version 5.4-rc-1 prior to 15.10.15, 16.x prior to 16.4.6
  and 16.5.x prior to 16.10.0.");

  script_tag(name:"solution", value:"Update to version 15.10.15, 16.4.6, 16.10.0 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-gfp2-6qhm-7x43.nasl");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version:version, test_version_lo:"5.4-rc-1", test_version_up:"15.10.15" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.10.15", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"16.0.0", test_version_up:"16.4.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"16.4.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"16.5.0", test_version_up:"16.10.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"16.10.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}


exit( 99 );
