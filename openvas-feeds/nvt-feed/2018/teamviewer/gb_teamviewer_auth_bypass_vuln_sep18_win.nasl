# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teamviewer:teamviewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813898");
  script_version("2024-11-27T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-11-27 05:05:40 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-09-07 13:42:31 +0530 (Fri, 07 Sep 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-16550");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamViewer Authentication Bypass Vulnerability (Sep 2018) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/detected");

  script_tag(name:"summary", value:"TeamViewer is prone to an authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper brute-force authentication
  protection mechanism.");

  script_tag(name:"impact", value:"Successful exploitation would allow attackers to bypass the
  authentication protection mechanism and determine the correct value of the default 4-digit PIN.");

  script_tag(name:"affected", value:"TeamViewer versions 10.x through 13.x.");

  script_tag(name:"solution", value:"TeamViewer has changed the default password strength from 4
  digits to 6 characters. Update to TeamViewer version 10.0.134865, 11.0.133222, 12.0.181268,
  13.2.36215 or later.");

  script_xref(name:"URL", value:"https://community.teamviewer.com/t5/Announcements/Statement-on-recent-brute-force-research-CVE-2018-16550/m-p/43215");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version:version, test_version_lo:"10.0", test_version_up:"10.0.134865" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.0.134865", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"11.0", test_version_up:"11.0.133222" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.0.133222", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"12.0", test_version_up:"12.0.181268" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"12.0.181268", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"13.0", test_version_up:"13.2.36215" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"13.2.36215", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
