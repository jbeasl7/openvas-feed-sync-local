# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801671");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0121", "CVE-2010-4377", "CVE-2010-4378",
                "CVE-2010-4396", "CVE-2010-4388", "CVE-2010-4389",
                "CVE-2010-4390", "CVE-2010-4391", "CVE-2010-4392",
                "CVE-2010-4394", "CVE-2010-4395");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Dec 2010) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38550/");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/12102010_player/en/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary
  code or cause a denial of service.");
  script_tag(name:"affected", value:"RealPlayer SP 1.0 to 1.1.5 (12.x)
  RealNetworks RealPlayer SP 11.0 to 11.1 on Windows platform.");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the 'Cook' codec initialization function

  - Heap-based buffer overflow when parsing of 'Cook' codec
    information in a Real Audio file with many subbands

  - Memory corruption error in parsing of a 'RV20' video stream

  - Cross-site scripting in ActiveX control and several HTML files

  - Heap-based buffer overflow errors in the cook codec functions

  - Heap-based buffer overflow when parsing 'AAC', 'IVR',
    'RealMedia', and 'RealPix' files");
  script_tag(name:"solution", value:"Upgrade to RealPlayer 14.0.1.609 (Build 12.0.1.609) or later.");
  script_tag(name:"summary", value:"RealPlayer is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(isnull(rpVer)){
  exit(0);
}

## Realplayer version 11.x, 1.x(12.x)
if(version_in_range(version:rpVer, test_version:"11.0.0", test_version2:"11.0.0.674") ||
   version_in_range(version:rpVer, test_version:"12.0.0", test_version2:"12.0.0.879")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
