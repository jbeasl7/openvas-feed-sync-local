# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902621");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_cve_id("CVE-2011-2945", "CVE-2011-2947", "CVE-2011-2950", "CVE-2011-2951",
                "CVE-2011-2954");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Aug 2011) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44014/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49172");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49173");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49178");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49196");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49199");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/08162011_player/en/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary
  code or cause a denial of service.");
  script_tag(name:"affected", value:"RealPlayer versions 11.0 through 11.1
  RealPlayer SP versions 1.0 through 1.1.5 (12.x)
  RealPlayer versions 14.0.0 through 14.0.5");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A cross-zone scripting error in the ActiveX which allows remote attackers
    to inject arbitrary web script in the Local Zone via a local HTML document.

  - A buffer overflow error which allows remote attackers to execute arbitrary
    code via a crafted raw_data_frame field in an AAC file and a crafted QCP
    file.

  - An use-after-free error in the AutoUpdate feature which allows remote
    attackers to execute arbitrary code via unspecified vectors.");
  script_tag(name:"solution", value:"Upgrade to RealPlayer version 14.0.6 or later.");
  script_tag(name:"summary", value:"RealPlayer is prone to multiple vulnerabilities");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(isnull(rpVer)){
  exit(0);
}

if(version_in_range(version:rpVer, test_version:"11.0.0", test_version2:"11.0.2.2315") ||
   version_in_range(version:rpVer, test_version:"12.0.0", test_version2:"12.0.0.879") ||
   version_in_range(version:rpVer, test_version:"12.0.1", test_version2:"12.0.1.660")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
