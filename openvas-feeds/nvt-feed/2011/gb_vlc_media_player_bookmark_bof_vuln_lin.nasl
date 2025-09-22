# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801781");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_cve_id("CVE-2011-1087");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("VLC Media Player 'Bookmark Creation' Buffer Overflow Vulnerability - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38569");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_mandatory_keys("VLCPlayer/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the application. Failed attacks will cause denial-of-service
  conditions.");
  script_tag(name:"affected", value:"VLC media player version prior to 1.0.6 on Linux");
  script_tag(name:"insight", value:"The flaw is due to a race condition error when creating bookmarks and
  can be exploited to corrupt memory by tricking a user into creating a
  bookmark while playing a specially crafted file.");
  script_tag(name:"solution", value:"Upgrade to the VLC media player version 1.0.6 or later.");
  script_tag(name:"summary", value:"VLC Media Player is prone to a buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vlcVer = get_kb_item("VLCPlayer/Lin/Ver");
if(!vlcVer){
  exit(0);
}

if(version_in_range(version:vlcVer, test_version:"1.0", test_version2:"1.0.5")){
  report = report_fixed_ver(installed_version:vlcVer, vulnerable_range:"1.0 - 1.0.5");
  security_message(port: 0, data: report);
}
