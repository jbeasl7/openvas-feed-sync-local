# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812504");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2017-17670");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-26 15:11:00 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2017-12-20 11:58:25 +0530 (Wed, 20 Dec 2017)");

  script_tag(name:"qod_type", value:"registry");

  script_name("VLC Media Player 'MP4 Demux Module' DoS Vulnerability - Windows");

  script_tag(name:"summary", value:"VLC media player is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a type conversion error
  in 'modules/demux/mp4/libmp4.c' in the MP4 demux module leading to an invalid
  free, because the type of a box may be changed between a read operation and a
  free operation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial-of-service condition. Given the nature of this
  issue, attackers may also be able to execute arbitrary code, but this has not
  been confirmed.");

  script_tag(name:"affected", value:"VideoLAN VLC media player 2.2.8 and prior
  on Windows.");

  script_tag(name:"solution", value:"Update to version 3.0.1 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/12/15/1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102214");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vlcVer = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vlcVer, test_version:"2.2.8")) {
  report = report_fixed_ver( installed_version:vlcVer, fixed_version:"3.0.1", install_path:path );
  security_message(data:report);
  exit(0);
}

exit(0);
