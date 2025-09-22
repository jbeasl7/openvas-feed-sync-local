# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124689");
  script_version("2024-09-23T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-09-23 05:05:44 +0000 (Mon, 23 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-11 08:30:39 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-20 19:55:54 +0000 (Fri, 20 Sep 2024)");

  script_cve_id("CVE-2024-45591");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 1.8 < 15.10.9, 16.0.0-rc-1 < 16.3.0-rc-1 Information Disclosure Vulnerability (GHSA-pvmm-55r5-g3mm)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The REST API exposes the history of any page in XWiki of which
  the attacker knows the name. The exposed information includes the time of each modification, the
  version number, the author (both username and display name), and the version comment. This
  information is exposed regardless of the rights setup, and even when the wiki is configured to be
  fully private.");

  script_tag(name:"affected", value:"XWiki version 1.8 prior to 15.10.9 and 16.0.0-rc-1
  prior to 16.3.0-rc-1.");

  script_tag(name:"solution", value:"Update to version 15.10.9, 16.3.0-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-pvmm-55r5-g3mm");

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

if( version_in_range_exclusive( version:version, test_version_lo:"1.8", test_version_up:"15.10.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.10.9", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"16.0.0-rc-1", test_version_up:"16.3.0-rc-1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"16.3.0-rc-1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
