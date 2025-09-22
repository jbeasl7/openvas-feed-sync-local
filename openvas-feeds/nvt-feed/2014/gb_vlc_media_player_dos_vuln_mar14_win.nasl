# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804346");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2013-7340");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-03-25 13:19:16 +0530 (Tue, 25 Mar 2014)");
  script_name("VLC Media Player Denial of Service Vulnerability (Mar 2014) - Windows");

  script_tag(name:"summary", value:"VLC Media Player is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists due to some unspecified error.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of service
conditions.");
  script_tag(name:"affected", value:"VLC media player version 2.0.6 and prior on Windows.");
  script_tag(name:"solution", value:"Upgrade to VLC media player version 2.0.7 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.videolan.org/developers/vlc-branch/NEWS");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

vlcVer = get_app_version(cpe:CPE);
if(!vlcVer){
  exit(0);
}

if(version_is_less(version:vlcVer, test_version:"2.0.7"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"2.0.7");
  security_message(port:0, data:report);
  exit(0);
}
