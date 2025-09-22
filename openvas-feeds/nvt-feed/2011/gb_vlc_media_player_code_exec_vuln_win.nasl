# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902340");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2011-0531");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VLC Media Player '.mkv' Code Execution Vulnerability - Windows");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted MKV file.");
  script_tag(name:"affected", value:"VLC media player version 1.1.6.1 and prior on Windows");
  script_tag(name:"insight", value:"The flaw is due to an input validation error within the 'MKV_IS_ID'
  macro in 'modules/demux/mkv/mkv.hpp' of the MKV demuxer, when parsing the
  MKV file.");
  script_tag(name:"solution", value:"Upgrade to the VLC media player version 1.1.7 or later.");
  script_tag(name:"summary", value:"VLC Media Player is prone to an arbitrary code execution vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46060");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1025018");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"1.1.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.7", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
