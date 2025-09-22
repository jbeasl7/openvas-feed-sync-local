# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802922");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2012-3377");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-07-25 14:01:24 +0530 (Wed, 25 Jul 2012)");
  script_name("VLC Media Player OGG Demuxer Buffer Overflow Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49835");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54345");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/76800");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1027224");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/07/06/1");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/07/06/2");
  script_xref(name:"URL", value:"http://git.videolan.org/?p=vlc/vlc-2.0.git;a=commitdiff;h=16e9e126333fb7acb47d363366fee3deadc8331e");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code on
  the target system.");
  script_tag(name:"affected", value:"VLC media player versions prior to 2.0.2 on Windows");
  script_tag(name:"insight", value:"A boundary error exists within the 'Ogg_DecodePacket()' function
  (modules/demux/ogg.c) when processing OGG container files. This can be
  exploited to cause heap-based buffer overflow via a specially crafted OGG
  file.");
  script_tag(name:"solution", value:"Upgrade to VLC media player version 2.0.2 or later.");
  script_tag(name:"summary", value:"VLC Media Player is prone to a buffer overflow vulnerability.");
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

if( version_is_less( version:vers, test_version:"2.0.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.2", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
