# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801429");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_cve_id("CVE-2010-2937");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("VLC Media Player Meta-Information Denial of Service Vulnerability - Windows");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1004.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42386");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to crash the affected
  application, denying service to legitimate users.");
  script_tag(name:"affected", value:"VLC media player version prior to 1.1.3 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to an input validation error when trying to extract
  meta-informations about input media through 'ID3v2' tags.");
  script_tag(name:"solution", value:"Upgrade to the VLC media player version 1.1.3 or later.");
  script_tag(name:"summary", value:"VLC Media Player is prone to a denial of service (DoS) vulnerability.");
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

if( version_is_less( version:vers, test_version:"1.1.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.3", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
