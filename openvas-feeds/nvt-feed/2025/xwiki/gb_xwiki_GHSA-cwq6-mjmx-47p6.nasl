# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128086");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2025-01-23 12:10:52 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-30 16:02:40 +0000 (Wed, 30 Apr 2025)");

  script_cve_id("CVE-2024-55876");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 1.2-milestone-2 < 15.10.9, 16.0.0-rc-1 < 16.3.0 Incorrect Authorization Vulnerability (GHSA-cwq6-mjmx-47p6)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to an incorrect authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Scheduler in subwiki allows scheduling operations for any
  main wiki user.");

  script_tag(name:"affected", value:"XWiki version 1.2-milestone-2 prior to 15.10.9 and 16.0.0-rc-1
  prior to 16.3.0");

  script_tag(name:"solution", value:"Update to versions 15.10.9, 16.3.0 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-cwq6-mjmx-47p6.nasl");

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

if( version_in_range_exclusive( version:version, test_version_lo:"1.2-milestone-2", test_version_up:"15.10.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.10.9", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"16.0.0-rc-1", test_version_up:"16.3.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"16.3.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
