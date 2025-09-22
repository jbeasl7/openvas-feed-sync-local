# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805315");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2010-1445", "CVE-2010-1444", "CVE-2010-1443", "CVE-2010-1442",
                "CVE-2010-1441");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-01-05 12:51:20 +0530 (Mon, 05 Jan 2015)");
  script_name("VLC Media Player Multiple Vulnerabilities-03 (Jan 2015) - Mac OS X");

  script_tag(name:"summary", value:"VLC media player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple errors in the A/52 audio decoder, DTS audio decoder, MPEG audio
  decoder, AVI demuxer, ASF demuxer and Matroska demuxer.

  - An error when processing XSPF playlists.

  - A use-after-free error when attempting to create a playlist of the contents
  of a malformed zip archive.

  - An error in the RTMP implementation.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct a denial of service or potentially compromise a
  user's system.");

  script_tag(name:"affected", value:"VideoLAN VLC media player before 1.0.6
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to VideoLAN VLC media player
  version 1.0.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39558");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1003.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:vlcVer, test_version:"1.0.6"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"1.0.6");
  security_message(port: 0, data: report);
  exit(0);
}
