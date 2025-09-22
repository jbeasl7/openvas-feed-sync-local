# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813502");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-11516");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 21:00:00 +0000 (Fri, 03 Mar 2023)");
  script_tag(name:"creation_date", value:"2018-05-29 12:32:46 +0530 (Tue, 29 May 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VLC Media Player Denial-of-Service Vulnerability (May 2018) - Mac OS X");

  script_tag(name:"summary", value:"VLC media player is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to an error in
  the 'vlc_demux_chained_Delete' function in input/demux_chained.c file while
  reading a crafted .swf file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (heap corruption and application crash)
  or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"VideoLAN VLC media player version 3.0.1
  on Mac OS X");

  script_tag(name:"solution", value:"Update to version 3.0.2 or above. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://code610.blogspot.in/2018/05/make-free-vlc.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vlcVer = infos["version"];
vlcpath = infos["location"];

if(vlcVer == "3.0.1")
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"3.0.2", install_path: vlcpath);
  security_message(data:report);
  exit(0);
}

exit(0);
