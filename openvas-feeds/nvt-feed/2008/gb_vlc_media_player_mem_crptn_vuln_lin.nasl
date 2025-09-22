# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800113");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2008-10-17 14:35:03 +0200 (Fri, 17 Oct 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-4558");
  script_name("VLC Media Player XSPF Playlist Memory Corruption Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_mandatory_keys("VLCPlayer/Lin/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32267/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31758");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2826/products");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/vlc-xspf-memory-corruption");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code by
  tricking a user into opening a specially crafted XSPF file or even can crash
  an affected application.");

  script_tag(name:"affected", value:"VLC media player 0.9.2 and prior Linux.");

  script_tag(name:"insight", value:"The flaw exists due to VLC (xspf.c) library does not properly perform bounds
  checking on an identifier tag from an XSPF file before using it to index an array on the heap.");

  script_tag(name:"solution", value:"Upgrade to Version 0.9.3 or later.");

  script_tag(name:"summary", value:"VLC Media Player is prone to a memory corruption vulnerability.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers ,test_version:"0.9.2") ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.9.3", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
