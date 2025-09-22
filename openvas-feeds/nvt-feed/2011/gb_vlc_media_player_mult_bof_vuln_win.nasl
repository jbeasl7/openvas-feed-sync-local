# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801565");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)");
  script_cve_id("CVE-2010-3907");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VLC Media Player Real Demuxer File Handling Array Indexing Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1007.html");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3345");
  script_xref(name:"URL", value:"http://www.cs.brown.edu/people/drosenbe/research.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name:"insight", value:"This issue is caused by an array indexing error in the 'Close()' and
  'DemuxAudioMethod1()' [modules/demux/real.c] functions within the Real
   demuxer when processing a Real Media file with a zero 'i_subpackets' value.");
  script_tag(name:"solution", value:"Upgrade to VLC version 1.1.6 or apply patch from below link.");
  script_tag(name:"summary", value:"VLC media player is prone to array indexing vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to crash an affected application
  or compromise a vulnerable system by convincing a user to open a malicious media
  file or to visit a specially crafted web page.");
  script_tag(name:"affected", value:"VLC Media Player version 1.1.5 and prior.");
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

# VLC Media Player Version 1.1.5 and prior.
if( version_is_less( version:vers, test_version:"1.1.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.6", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
