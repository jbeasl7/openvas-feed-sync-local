# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124691");
  script_version("2025-02-10T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-02-10 05:38:01 +0000 (Mon, 10 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-09-20 11:25:36 +0000 (Fri, 20 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-07 15:48:36 +0000 (Fri, 07 Feb 2025)");

  script_cve_id("CVE-2024-46978", "CVE-2024-46979");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 13.2-rc-1 < 14.10.21, 15.0-rc-1 < 15.5.5, 15.6-rc-1 < 15.10.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-46978: It's possible for any user knowing the ID of a notification filter preference
  of another user, to enable/disable it or even delete it.

  - CVE-2024-46979: It's possible to get access to notification filters of any user by using
  a URL.");

  script_tag(name:"affected", value:"XWiki version 13.2-rc-1 prior to 14.10.21, 15.0-rc-1 prior to
  15.5.5 and 15.6-rc-1 prior to 15.10.1.");

  script_tag(name:"solution", value:"Update to version 14.10.21, 15.5.5, 15.10.1 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-pg4m-3gp6-hw4w");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-r95w-889q-x2gx");

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

if( version_in_range_exclusive( version:version, test_version_lo:"13.2-rc-1", test_version_up:"14.10.21" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.21", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.0-rc-1", test_version_up:"15.5.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.5.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.6-rc-1", test_version_up:"15.10.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.10.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
