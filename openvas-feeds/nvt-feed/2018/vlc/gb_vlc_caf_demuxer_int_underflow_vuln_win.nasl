# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814375");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-19857");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-25 17:15:00 +0000 (Thu, 25 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-12-17 10:49:31 +0530 (Mon, 17 Dec 2018)");
  script_tag(name:"qod", value:"50"); # Not able to detect the patch level
  script_name("VLC Media Player CAF Demuxer Integer Underflow Vulnerability - Windows");

  script_tag(name:"summary", value:"VLC media player is prone to an integer underflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper handling
  of magic cookies in Core Audio Format (CAF) files, which could result in an
  uninitialized memory read in the CAF demuxer.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of affected application and failed
  exploit attempts will likely result in denial of service conditions.");

  script_tag(name:"affected", value:"VideoLAN VLC media player versions 3.0.4 on Windows");

  script_tag(name:"solution", value:"Apply patch from Reference link. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://dyntopia.com/advisories/013-vlc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vlcVer = infos["version"];
vlcpath = infos["location"];

if(version_is_equal(version:vlcVer, test_version:"3.0.4"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"3.0.4", install_path: vlcpath);
  security_message(data:report);
  exit(0);
}
exit(99);
