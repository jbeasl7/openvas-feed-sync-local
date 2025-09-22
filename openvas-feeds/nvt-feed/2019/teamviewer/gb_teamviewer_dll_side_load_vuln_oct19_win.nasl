# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teamviewer:teamviewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107736");
  script_version("2024-11-27T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-11-27 05:05:40 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-10-26 14:04:11 +0200 (Sat, 26 Oct 2019)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-18 16:15:00 +0000 (Mon, 18 Nov 2019)");

  script_cve_id("CVE-2019-18196");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamViewer DLL Side Loading Vulnerability (Oct 2019) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/detected");

  script_tag(name:"summary", value:"TeamViewer is prone to a DLL side loading vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A DLL side loading vulnerability in the Windows Service in
  TeamViewer on Windows could allow an attacker to perform code execution on a target system via a
  service restart where the DLL was previously installed with administrative privileges.

  Exploitation requires that an attacker be able to create a new file in the TeamViewer application
  directory, directory permissions restrict that by default.");

  script_tag(name:"affected", value:"TeamViewer versions through 11.0.133222, 12.x through
  12.0.181268, 13.x through 13.2.36215 and 14.x through 14.6.4835.");

  script_tag(name:"solution", value:"Update to version 11.0.214397, 12.0.214399, 13.2.36216,
  14.7.1965 or later.");

  script_xref(name:"URL", value:"https://community.teamviewer.com/t5/Announcements/Security-bulletin-CVE-2019-18196/td-p/74564");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"11.0.214397" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.0.214397", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"12.0", test_version_up:"12.0.214399" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"12.0.214399", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"13.0", test_version_up:"13.2.36216" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"13.2.36216", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"14.0", test_version_up:"14.7.1965" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.7.1965", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
