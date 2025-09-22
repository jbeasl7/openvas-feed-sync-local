# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124824");
  script_version("2025-05-02T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-05-02 05:40:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"creation_date", value:"2025-04-23 12:10:52 +0000 (Wed, 23 Apr 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-30 16:09:17 +0000 (Wed, 30 Apr 2025)");

  script_cve_id("CVE-2025-32968");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 1.6 < 15.10.16, 16.0.0 < 16.4.6, 16.5.0 < 16.10.1 SQLi Vulnerability (GHSA-g9jj-75mx-wjcx)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible for a user with SCRIPT right to escape from
  the HQL execution context and perform a blind SQL injection to execute arbitrary SQL statements
  on the database backend.");

  script_tag(name:"affected", value:"XWiki version 1.6 prior to 15.10.16, 16.0.0 prior to
  16.4.6 and 16.5.0 prior to 16.10.1.");

  script_tag(name:"solution", value:"Update to version 15.10.16, 16.4.6, 16.10.1 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-g9jj-75mx-wjcx");

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

if( version_in_range_exclusive( version:version, test_version_lo:"1.6", test_version_up:"15.10.16" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.10.16", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"16.0.0", test_version_up:"16.4.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"16.4.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"16.5.0", test_version_up:"16.10.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"16.10.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
