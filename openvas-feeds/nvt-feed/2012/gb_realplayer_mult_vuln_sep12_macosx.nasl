# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803031");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2012-2407", "CVE-2012-2408", "CVE-2012-2409", "CVE-2012-2410",
                "CVE-2012-3234");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-09-21 16:44:53 +0530 (Fri, 21 Sep 2012)");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Sep 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50580");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55473");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027510");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/09072012_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_realplayer_detect_macosx.nasl");
  script_mandatory_keys("RealPlayer/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  on the system or cause the application to crash.");
  script_tag(name:"affected", value:"RealPlayer version 12.0.0.1701 and prior on Mac OS X");
  script_tag(name:"insight", value:"Multiple errors caused, when

  - Unpacking AAC stream

  - Decoding AAC SDK

  - Handling RealMedia files, which can be exploited to cause a buffer
    overflow.");
  script_tag(name:"solution", value:"Upgrade to RealPlayer version 12.0.1.1750 or later.");
  script_tag(name:"summary", value:"RealPlayer is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/MacOSX/Version");
if(!rpVer){
  exit(0);
}

if(version_is_less(version: rpVer, test_version:"12.0.1.1750")){
  report = report_fixed_ver(installed_version:rpVer, fixed_version:"12.0.1.1750");
  security_message(port:0, data:report);
}
