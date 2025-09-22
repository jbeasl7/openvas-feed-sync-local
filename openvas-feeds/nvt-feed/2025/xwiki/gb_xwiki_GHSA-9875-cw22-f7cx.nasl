# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124857");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-18 05:10:52 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-49581");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 11.10.11 < 16.4.7, 16.5.0-rc-1 < 16.10.3, 17.0.0-rc-1 < 17.0.0 RCE Vulnerability (GHSA-9875-cw22-f7cx)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Any user with edit right on a page
  (could be the user's profile) can execute code (Groovy, Python, Velocity) with programming right
  by defining a wiki macro. This allows full access to the whole XWiki installation and thus
  impacts its confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"XWiki version 11.10.11 prior to 16.4.7, 16.5.0-rc-1 prior
  to 16.10.3 and 17.0.0-rc-1 prior to 17.0.0.");

  script_tag(name:"solution", value:"Update to version 16.4.7, 16.10.3, 17.0.0 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-9875-cw22-f7cx");

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

if( version_in_range_exclusive( version:version, test_version_lo:"11.10.11", test_version_up:"16.4.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"16.4.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"16.5.0-rc-1", test_version_up:"16.10.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"16.10.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"17.0.0-rc-1", test_version_up:"17.0.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"17.0.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
