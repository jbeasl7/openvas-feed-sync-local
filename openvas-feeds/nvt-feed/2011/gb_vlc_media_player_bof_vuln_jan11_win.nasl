# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801726");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-01-31 05:37:34 +0100 (Mon, 31 Jan 2011)");
  script_cve_id("CVE-2011-0021");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VLC Media Player 'CDG decoder' Multiple Buffer Overflow Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0185");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/01/20/3");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to crash the affected
  application, or execute arbitrary code by convincing a user to open a
  malicious CD+G (CD+Graphics) media file or visit a specially crafted web
  page.");
  script_tag(name:"affected", value:"VLC media player version prior to 1.1.6 on Windows.");
  script_tag(name:"insight", value:"The flaws are due to an array indexing errors in the 'DecodeTileBlock()'
  and 'DecodeScroll()' [modules/codec/cdg.c] functions within the CDG decoder
  module when processing malformed data.");
  script_tag(name:"solution", value:"Upgrade to the VLC media player version 1.1.6 or later.");
  script_tag(name:"summary", value:"VLC Media Player is prone to multiple buffer overflow vulnerabilities.");
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

if( version_is_less( version:vers, test_version:"1.1.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.6", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
