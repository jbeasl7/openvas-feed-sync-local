# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802480");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2012-0023", "CVE-2011-5231");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-11-02 12:41:07 +0530 (Fri, 02 Nov 2012)");
  script_name("VLC Media Player TiVo Demuxer Double Free Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47325");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51147");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51231");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1026449");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71916");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1108.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to crash an affected
  application and denying service to legitimate users.");
  script_tag(name:"affected", value:"VLC media player version 0.9.0 to 1.1.12 on Windows");
  script_tag(name:"insight", value:"The flaw is due to a double-free error within the 'get_chunk_header()'
  function in 'modules/demux/ty.c' of the TiVo demuxer when opening a specially
  crafted TiVo (*.ty) file.");
  script_tag(name:"solution", value:"Upgrade VLC media player to 1.1.13 or later.");
  script_tag(name:"summary", value:"VLC Media Player is prone to double free vulnerability.");
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

if( version_in_range( version:vers, test_version:"0.9.0", test_version2:"1.1.12" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.13", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
