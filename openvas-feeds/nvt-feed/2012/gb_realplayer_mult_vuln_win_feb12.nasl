# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802800");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2012-0922", "CVE-2012-0923", "CVE-2012-0924", "CVE-2012-0925",
                "CVE-2012-0926", "CVE-2012-0927");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-02-21 13:01:53 +0530 (Tue, 21 Feb 2012)");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Feb 2012) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47896/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51883");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51884");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51885");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51887");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51888");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51889");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026643");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/02062012_player/en/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary
  code.");
  script_tag(name:"affected", value:"RealPlayer versions 11.x and 14.x
  RealPlayer versions 15.x before 15.02.71
  RealPlayer SP versions 1.0 through 1.1.5 (12.0.0.879)");
  script_tag(name:"insight", value:"The flaws are due to

  - An unspecified error in rvrender.dll, which allows to execute arbitrary
    code via a crafted flags in an RMFF file.

  - Improper handling of the frame size array by the RV20 codec, which allows
    to execute arbitrary code via a crafted RV20 RealVideo video stream.

  - Unspecified errors when processing VIDOBJ_START_CODE segments and
    coded_frame_size value in RealAudio audio stream.

  - An unspecified error in the RV40 and RV10 codec, which allows to execute
    arbitrary code via a crafted RV40 or RV10 RealVideo video stream.");
  script_tag(name:"solution", value:"Upgrade to RealPlayer version 15.02.71 or later.");
  script_tag(name:"summary", value:"RealPlayer is prone to multiple vulnerabilities");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(isnull(rpVer)){
  exit(0);
}

# versions 14 comes as 12.0.1
if((rpVer =~ "^11\.*") || (rpVer =~ "^12\.0\.1\.*") ||
   version_in_range(version:rpVer, test_version:"12.0.0", test_version2:"12.0.0.879") ||
   version_in_range(version:rpVer, test_version:"15.0.0", test_version2:"15.0.1.13")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
