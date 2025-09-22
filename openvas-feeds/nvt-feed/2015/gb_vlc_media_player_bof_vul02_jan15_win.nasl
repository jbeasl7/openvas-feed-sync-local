# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805313");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2010-2062");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-01-02 12:58:41 +0530 (Fri, 02 Jan 2015)");
  script_name("VLC Media Player 'real_get_rdt_chunk' BOF Vulnerability-02 (Jan 2015) - Windows");

  script_tag(name:"summary", value:"VLC media player is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists due to an integer
  underflow in the 'real_get_rdt_chunk' function within
  modules/access/rtsp/real.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to execute an arbitrary code within the context of the VLC
  media player and potentially compromise a user's system.");

  script_tag(name:"affected", value:"VideoLAN VLC media player before 1.0.1
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to VideoLAN VLC media player
  version 1.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36037/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2009/Jul/418");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/cve/CVE-2010-2062");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:vlcVer, test_version:"1.0.1"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"1.0.1");
  security_message(port: 0, data: report);
  exit(0);
}
