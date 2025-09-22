# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801507");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0117", "CVE-2010-0116", "CVE-2010-0120",
                "CVE-2010-3000", "CVE-2010-3001");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-5/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42775");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/08262010_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
  codes within the context of the application and can cause heap overflow
  or allow remote code execution.");
  script_tag(name:"affected", value:"RealPlayer SP 1.0 to 1.1.4 (12.x)
  RealNetworks RealPlayer SP 11.0 to 11.1 on Windows platform.");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the handling of dimensions during 'YUV420'
    transformations, which allows attackers to execute arbitrary code via
    crafted MP4 content.

  - An integer overflow error in the handling of crafted QCP file.

  - A heap-based buffer overflow when handling large size values in 'QCP'
    audio content.

  - An integer overflows in the 'ParseKnownType()' function, which allows
    attackers to execute arbitrary code via crafted 'HX_FLV_META_AMF_TYPE_MIXEDARRAY'
    or 'HX_FLV_META_AMF_TYPE_ARRAY' data in an FLV file.

  - An unspecified error in an ActiveX control in the Internet Explorer (IE)
    plugin, has unknown impact and attack vectors related to
    'multiple browser windows.'");
  script_tag(name:"solution", value:"Upgrade to RealPlayer SP version 1.1.5.");
  script_tag(name:"summary", value:"RealPlayer is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
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
   version_in_range(version:rpVer, test_version:"12.0.0", test_version2:"12.0.0.873")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

