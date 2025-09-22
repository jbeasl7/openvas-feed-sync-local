# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807929");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2016-3941");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-30 03:05:00 +0000 (Wed, 30 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-04-26 11:09:19 +0530 (Tue, 26 Apr 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VLC Media Player Denial of Service Vulnerability (Apr 2016) - Windows");

  script_tag(name:"summary", value:"VLC media player is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the buffer overflow in
  the 'AStreamPeekStream' function in 'input/stream.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (crash) and possibly execute arbitrary
  code via crafted wav file.");

  script_tag(name:"affected", value:"VideoLAN VLC media player before 2.2.0
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to VideoLAN VLC media player version
  2.2.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1035456");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/vlc/+bug/1533633");

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

if(version_is_less(version:vlcVer, test_version:"2.2.0"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"2.2.0");
  security_message(data:report);
  exit(0);
}
