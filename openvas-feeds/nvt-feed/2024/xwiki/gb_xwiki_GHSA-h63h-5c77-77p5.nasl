# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124681");
  script_version("2024-09-09T05:05:49+0000");
  script_tag(name:"last_modification", value:"2024-09-09 05:05:49 +0000 (Mon, 09 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-08-02 05:30:39 +0000 (Fri, 02 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-06 20:54:20 +0000 (Fri, 06 Sep 2024)");

  script_cve_id("CVE-2024-37901");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 9.2-rc-1 < 14.10.21, 15.0-rc-1 < 15.5.5, 15.6-rc-1 < 15.10.2 RCE Vulnerability (GHSA-h63h-5c77-77p5)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Any user with edit right on any page can perform arbitrary
  remote code execution by adding instances of XWiki.SearchSuggestConfig and
  XWiki.SearchSuggestSourceClass to their user profile or any other page.");

  script_tag(name:"affected", value:"XWiki version 9.2-rc-1 prior to 14.10.21, 15.0-rc-1
  prior to 15.5.5 and 15.6-rc-1 prior to 15.10.2.");

  script_tag(name:"solution", value:"Update to version 14.10.21, 15.5.5, 15.10.2 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-h63h-5c77-77p5");

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

if( version_in_range_exclusive( version:version, test_version_lo:"9.2-rc-1", test_version_up:"14.10.21" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.21", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.0-rc-1", test_version_up:"15.5.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.5.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.6-rc-1", test_version_up:"15.10.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.10.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
