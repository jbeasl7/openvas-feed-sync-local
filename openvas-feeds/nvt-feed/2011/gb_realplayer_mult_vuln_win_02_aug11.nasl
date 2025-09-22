# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902624");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_cve_id("CVE-2011-2946", "CVE-2011-2948", "CVE-2011-2949", "CVE-2011-2952",
                "CVE-2011-2953", "CVE-2011-2955", "CVE-2011-2947");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Aug 2011) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45608/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49174");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49175");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49195");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49198");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49200");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49202");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49996");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44014/");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/08162011_player/en/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/RealPlayer_or_Enterprise/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary
  code or cause a denial of service.");
  script_tag(name:"affected", value:"RealPlayer versions 11.0 through 11.1
  RealPlayer SP versions 1.0 through 1.1.5 (12.x)
  RealPlayer versions 14.0.0 through 14.0.5
  RealPlayer Enterprise versions 2.0 through 2.1.5");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Unspecified errors in an ActiveX control in the browser plugin.

  - Improper handling of DEFINEFONT fields in SWF files which allows remote
    attackers to execute arbitrary code via a crafted file.

  - A buffer overflow error which allows remote attackers to execute arbitrary
    code via a crafted raw_data_frame field in an AAC file and crafted ID3v2
    tags in an MP3 file.

  - An use-after-free error allows remote attackers to execute arbitrary code
    via vectors related to a dialog box and a modal dialog box.");
  script_tag(name:"solution", value:"Upgrade to RealPlayer version 14.0.6 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"RealPlayer is prone to multiple vulnerabilities");
  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
rpenVer = get_kb_item("RealPlayer-Enterprise/Win/Ver");
if(isnull(rpVer) && isnull(rpenVer)){
  exit(0);
}

if(version_in_range(version:rpVer, test_version:"11.0.0", test_version2:"11.0.2.2315") ||
   version_in_range(version:rpVer, test_version:"12.0.0", test_version2:"12.0.0.879") ||
   version_in_range(version:rpVer, test_version:"12.0.1", test_version2:"12.0.1.660") ||
   version_in_range(version:rpenVer, test_version:"6.0.12.1748", test_version2:"6.0.12.1830")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
