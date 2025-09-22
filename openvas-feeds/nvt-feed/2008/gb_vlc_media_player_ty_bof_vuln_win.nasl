# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800116");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-10-22 15:17:54 +0200 (Wed, 22 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4654", "CVE-2008-4686");
  script_name("VLC Media Player TY Processing Buffer Overflow Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");

  script_xref(name:"URL", value:"http://www.videolan.org/security/sa0809.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31813");
  script_xref(name:"URL", value:"http://www.trapkit.de/advisories/TKADV2008-010.txt");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2856");
  script_xref(name:"URL", value:"http://git.videolan.org/?p=vlc.git;a=commitdiff;h=26d92b87bba99b5ea2e17b7eaa39c462d65e9133#patch1");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code
  by tricking a user into opening a specially crafted TY file or can even crash an affected application.");

  script_tag(name:"affected", value:"VLC media player 0.9.0 through 0.9.4 on Windows (Any).");

  script_tag(name:"insight", value:"The flaw is due to a boundary error while parsing the header of an
  invalid TY file.");

  script_tag(name:"summary", value:"VLC Media Player is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Update to Version 0.9.5 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:videolan:vlc_media_player";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "0.9.0", test_version2: "0.9.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.9.5", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
