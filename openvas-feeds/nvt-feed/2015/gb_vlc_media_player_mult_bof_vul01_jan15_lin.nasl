# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805309");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2011-3623");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-01-05 18:56:27 +0530 (Mon, 05 Jan 2015)");
  script_name("VLC Media Player Multiple Buffer Overflow Vulnerabilities-01 (Jan 2015) - Linux");

  script_tag(name:"summary", value:"VLC media player is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to overflow conditions
  in the,

  - ASF_ObjectDumpDebug function within modules/demux/asf/libasf.c script,

  - AVI_ChunkDumpDebug_level function within modules/demux/avi/libavi.c script,

  - AVI_ChunkDumpDebug_level function within modules/demux/avi/libavi.c script

  - MP4_BoxDumpStructure function within modules/demux/mp4/libmp4.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct a denial of service attack or potentially the execution
  of arbitrary code.");

  script_tag(name:"affected", value:"VideoLAN VLC media player before 1.0.2
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to VideoLAN VLC media player
  version 1.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_xref(name:"URL", value:"http://www.videolan.org/security/sa0901.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/cve/CVE-2011-3623");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_mandatory_keys("VLCPlayer/Lin/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:vlcVer, test_version:"1.0.2"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"1.0.2");
  security_message(port: 0, data: report);
  exit(0);
}
