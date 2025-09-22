# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801783");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_cve_id("CVE-2011-1684");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("VLC Media Player 'MP4_ReadBox_skcr()' Buffer Overflow Vulnerability - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44022");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47293");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66664");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0916");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_mandatory_keys("VLCPlayer/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a malicious file or visiting a specially crafted
  web page.");
  script_tag(name:"affected", value:"VLC media player version prior to 1.1.9 on Linux");
  script_tag(name:"insight", value:"The flaw is caused by a heap corruption error in the 'MP4_ReadBox_skcr()'
  [modules/demux/mp4/libmp4.c] function when processing malformed MP4
  (MPEG-4 Part 14) data.");
  script_tag(name:"solution", value:"Upgrade to the VLC media player version 1.1.9 or later.");
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

if(version_is_less(version:vlcVer, test_version:"1.1.9")){
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"1.1.9");
  security_message(port: 0, data: report);
}
