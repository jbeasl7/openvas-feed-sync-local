# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801676");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0121", "CVE-2010-2579", "CVE-2010-2997",
                "CVE-2010-2999", "CVE-2010-4375", "CVE-2010-4376",
                "CVE-2010-4377", "CVE-2010-4378", "CVE-2010-4379",
                "CVE-2010-4382", "CVE-2010-4383", "CVE-2010-4384",
                "CVE-2010-4385", "CVE-2010-4386", "CVE-2010-4387",
                "CVE-2010-4389", "CVE-2010-4390", "CVE-2010-4392",
                "CVE-2010-4395", "CVE-2010-4397");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Dec 2010) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-5/");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/08262010_player/en/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_realplayer_detect_lin.nasl");
  script_mandatory_keys("RealPlayer/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary
  code or cause a denial of service.");

  script_tag(name:"affected", value:"RealPlayer Version 11.0.2.1744 on Linux platform.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the 'Cook' codec initialization function

  - Heap-based buffer overflow when parsing of 'Cook' codec information in a
    Real Audio file with many subbands

  - Memory corruption error in parsing of a 'RV20' video stream

  - Cross-site scripting in ActiveX control and several HTML files

  - Heap-based buffer overflow errors in the cook codec functions

  - Heap-based buffer overflow when parsing 'AAC', 'IVR', 'RealMedia',
    'RA5' and 'SIPR' files

  - Integer overflow in the handling of frame dimensions in a 'SIPR' stream

  - Heap-based buffer overflow error when parsing a large Screen Width value
    in the Screen Descriptor header of a GIF87a file in an RTSP stream

  - An integer overflow in the pnen3260.dll module allows remote attackers to
    execute arbitrary code via a crafted TIT2 atom in an AAC file

  - An use-after-free error allows remote attackers to execute arbitrary code
    or cause a denial of service via a crafted StreamTitle tag in an ICY
    SHOUTcast stream, related to the SMIL file format

  - An integer overflow error allows remote attackers to execute arbitrary
    code or cause a denial of service via a malformed MLLT atom in an AAC file

  - Heap-based buffer overflow when handling of multi-rate audio streams");

  script_tag(name:"solution", value:"Upgrade to RealPlayer version 11.0.2.2315 or later.");

  script_tag(name:"summary", value:"RealPlayer is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Linux/Ver");
if(isnull(rpVer)){
  exit(0);
}

if(version_is_less(version:rpVer, test_version:"11.0.2.2315")) {
  report = report_fixed_ver(installed_version:rpVer, vulnerable_range:"Less than 11.0.2.2315");
  security_message(port: 0, data: report);
}
