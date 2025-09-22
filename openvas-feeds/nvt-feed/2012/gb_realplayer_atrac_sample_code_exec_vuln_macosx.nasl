# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802802");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2012-0928");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-02-21 15:31:43 +0530 (Tue, 21 Feb 2012)");
  script_name("RealNetworks RealPlayer Atrac Sample Decoding Remote Code Execution Vulnerability - Mac OS X");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026643");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51890");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/02062012_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_realplayer_detect_macosx.nasl");
  script_mandatory_keys("RealPlayer/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary
  code.");
  script_tag(name:"affected", value:"RealPlayer versions 12.X through 12.0.0.1701 on Mac OS X");
  script_tag(name:"insight", value:"The flaw is due to an improper decoding of samples by ATRAC codec,
  which allows remote attackers to execute arbitrary code via a crafted ATRAC
  audio file.");
  script_tag(name:"solution", value:"Upgrade to RealPlayer version 12.0.0.1703 or later.");
  script_tag(name:"summary", value:"RealPlayer is prone to a remote code execution vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/MacOSX/Version");
if(isnull(rpVer)){
  exit(0);
}

if(version_in_range(version:rpVer, test_version:"12.0", test_version2:"12.0.0.1701")){
  report = report_fixed_ver(installed_version:rpVer, vulnerable_range:"12.0 - 12.0.0.1701");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
