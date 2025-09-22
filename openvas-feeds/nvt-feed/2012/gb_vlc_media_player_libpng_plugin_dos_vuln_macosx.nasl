# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802489");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2012-5470");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-11-02 14:31:32 +0530 (Fri, 02 Nov 2012)");
  script_name("VLC Media Player 'libpng_plugin' Denial of Service Vulnerability - Mac OS X");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/21889/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55850");
  script_xref(name:"URL", value:"http://www.videolan.org/vlc/releases/2.0.4.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/10/24/3");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to crash the affected
  application and denying service to legitimate users.");
  script_tag(name:"affected", value:"VLC media player version 2.0.3 and prior on Mac OS X");
  script_tag(name:"insight", value:"The flaw is due to an error in 'libpng_plugin' when handling a crafted PNG
  file. Which can be exploited to cause a crash.");
  script_tag(name:"solution", value:"Upgrade to VLC media player 2.0.4 or later.");
  script_tag(name:"summary", value:"VLC Media Player is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vlcVer = get_kb_item("VLC/Media/Player/MacOSX/Version");
if(!vlcVer){
  exit(0);
}

if(version_is_less(version:vlcVer, test_version:"2.0.4")){
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"2.0.4");
  security_message(port:0, data:report);
}
