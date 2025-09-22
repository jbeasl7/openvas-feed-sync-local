# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902341");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2011-0522");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("VLC Media Player USF and Text Subtitles Decoders BOF Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46008");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16108/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0225");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to crash an affected application
  or execute arbitrary code by convincing a user to open a malicious media file.");
  script_tag(name:"affected", value:"VLC media player version 1.x before 1.1.6-rc");
  script_tag(name:"insight", value:"The flaws are caused by buffer overflow errors in the 'StripTags()' function
  within the USF and Text subtitles decoders 'modules/codec/subtitles/subsdec.c'
  and 'modules/codec/subtitles/subsusf.c' when processing malformed data.");
  script_tag(name:"solution", value:"Upgrade to the VLC media player version 1.1.6-rc or later.");
  script_tag(name:"summary", value:"VLC Media Player is prone to buffer overflow vulnerabilities.");
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

if( version_in_range( version:vers, test_version:"1.1", test_version2:"1.1.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.6-rc", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
