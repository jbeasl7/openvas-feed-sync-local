# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808221");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2016-5108");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-06-13 13:25:43 +0530 (Mon, 13 Jun 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VLC Media Player QuickTime IMA File Denial of Service Vulnerability (Jun 2016) - Windows");

  script_tag(name:"summary", value:"VLC media player is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a buffer overflow
  vulnerability in the 'DecodeAdpcmImaQT' function in 'modules/codec/adpcm.c'
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (crash) and possibly execute arbitrary
  code via crafted QuickTime IMA file.");

  script_tag(name:"affected", value:"VideoLAN VLC media player before 2.2.4
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to VideoLAN VLC media player version
  2.2.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1036009");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1601.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:vlcVer, test_version:"2.2.4"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"2.2.4");
  security_message(data:report);
  exit(0);
}
