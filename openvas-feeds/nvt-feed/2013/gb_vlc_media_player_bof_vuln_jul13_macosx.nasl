# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803699");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2013-1954");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-07-16 13:56:02 +0530 (Tue, 16 Jul 2013)");
  script_name("VLC Media Player Buffer Overflow Vulnerability (Jul 2013) - Mac OS X");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code or cause denial of service condition in the context of affected application via crafted ASF file.");
  script_tag(name:"affected", value:"VLC media player version 2.0.5 and prior on Mac OS X.");
  script_tag(name:"insight", value:"Flaw due to error in 'DemuxPacket()' function in the ASF Demuxer component
(modules/demux/asf/asf.c) when parsing ASF files.");
  script_tag(name:"solution", value:"Upgrade to VLC media player version 2.0.6 or later.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"summary", value:"VLC Media Player is prone to a buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51995");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57333");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1302.html");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  exit(0);
}

include("version_func.inc");

vlcVer = get_kb_item("VLC/Media/Player/MacOSX/Version");
if(!vlcVer){
  exit(0);
}

if(version_is_less_equal(version:vlcVer, test_version:"2.0.5"))
{
  report = report_fixed_ver(installed_version:vlcVer, vulnerable_range:"Less than or equal to 2.0.5");
  security_message(port: 0, data: report);
  exit(0);
}
