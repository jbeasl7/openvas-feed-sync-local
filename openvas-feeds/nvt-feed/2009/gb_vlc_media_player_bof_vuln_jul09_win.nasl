# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800663");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2484");
  script_name("VLC Media Player SMB 'Win32AddConnection()' BOF Vulnerability (Jul 2009) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35500");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1714");
  script_xref(name:"URL", value:"http://git.videolan.org/?p=vlc.git;a=commit;h=e60a9038b13b5eb805a76755efc5c6d5e080180f");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code, and can
  cause application crash.");

  script_tag(name:"affected", value:"VLC Media Player version 0.9.9 and prior on Windows.");

  script_tag(name:"insight", value:"Stack-based Buffer overflow error in the 'Win32AddConnection' function in
  modules/access/smb.c while processing a specially crafted long 'smb://' URI within a playlist.");

  script_tag(name:"summary", value:"VLC Media Player is prone to Stack-Based Buffer Overflow Vulnerability.");

  script_tag(name:"solution", value:"Apply the available patch from the references or update to a later version.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"0.9.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
