# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802722");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2012-1775", "CVE-2012-1776");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-03-21 11:52:20 +0530 (Wed, 21 Mar 2012)");
  script_name("VLC Media Player Multiple Vulnerabilities (Mar 2012) - Windows");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1201.html");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1202.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service or
  possibly execute arbitrary code via crafted streams.");
  script_tag(name:"affected", value:"VLC media player version prior to 2.0.1 on Windows");
  script_tag(name:"insight", value:"The flaws are due to multiple buffer overflow errors in the
  application, which allows remote attackers to execute arbitrary code via
  crafted MMS:// stream and Real RTSP streams.");
  script_tag(name:"solution", value:"Upgrade to VLC media player version 2.0.1 or later.");
  script_tag(name:"summary", value:"VLC Media Player is prone to multiple vulnerabilities.");
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

if(version_is_less( version:vers, test_version:"2.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.1", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
