# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124627");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-04-15 05:30:39 +0000 (Mon, 15 Apr 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-09 18:50:19 +0000 (Thu, 09 Jan 2025)");

  script_cve_id("CVE-2024-31996");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 3.0.1 < 14.10.19, 15.0-rc-1 < 15.5.4, 15.6-rc-1 < 15.9-rc-1 RCE Vulnerability (GHSA-hf43-47q4-fhq5)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The HTML escaping of escaping tool that is used in XWiki
  doesn't escape {, which, when used in certain places, allows XWiki syntax injection and thereby
  remote code execution.");

  script_tag(name:"affected", value:"XWiki version 3.0.1 prior to 14.10.19, 15.0-rc-1
  prior to 15.5.4 and 15.6-rc-1 prior to 15.9-rc-1.");

  script_tag(name:"solution", value:"Update to version 14.10.19, 15.5.4, 15.9-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-commons/security/advisories/GHSA-hf43-47q4-fhq5");

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

if( version_in_range_exclusive( version:version, test_version_lo:"3.0.1", test_version_up:"14.10.19" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.19", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.0-rc-1", test_version_up:"15.5.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.5.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.6-rc-1", test_version_up:"15.9-rc-1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.9-rc-1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
