# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124670");
  script_version("2025-02-07T05:37:57+0000");
  script_tag(name:"last_modification", value:"2025-02-07 05:37:57 +0000 (Fri, 07 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-06-25 09:30:39 +0000 (Tue, 25 Jun 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-05 16:01:02 +0000 (Wed, 05 Feb 2025)");

  script_cve_id("CVE-2024-37899");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 13.4.7 < 14.10.21, 15.0-rc-1 < 15.5.5, 15.6-rc-1 < 15.10.6, 16.0.0-rc-1 < 16.0.0 RCE Vulnerability (GHSA-j584-j2vj-3f93)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When an admin disables a user account, the user's profile is
  executed with the admin's rights. This allows a user to place malicious code in the user profile
  before getting an admin to disable the user account.");

  script_tag(name:"affected", value:"XWiki version 13.4.7 prior to 13.5, 13.10.3 prior to 14.10.21,
  15.0-rc-1 prior to 15.5.5, 15.6-rc-1 prior to 15.10.6 and 16.0.0-rc-1 prior to 16.0.0.");

  script_tag(name:"solution", value:"Update to version 14.10.21, 15.5.5, 15.10.6, 16.0.0
  or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-j584-j2vj-3f93");
  script_xref(name:"URL", value:"https://jira.xwiki.org/browse/XWIKI-21611");

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

# nb: This is a special case because the vulnerability was introduced in versions 13.4.7 and 13.10.3, while 13.5 is unaffected because it was released prior to 13.4.7 (seems to be on the branch with 13.10.3).
if( version_in_range_exclusive( version:version, test_version_lo:"13.4.7", test_version_up:"13.5" ) || version_in_range_exclusive( version:version, test_version_lo:"13.10.3", test_version_up:"14.10.21" )) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.21", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.0-rc-1", test_version_up:"15.5.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.5.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"15.6-rc-1", test_version_up:"15.10.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.10.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"16.0.0-rc-1", test_version_up:"16.0.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"16.0.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
