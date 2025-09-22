# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902678");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-3402", "CVE-2012-0159");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-05-14 13:06:50 +0530 (Mon, 14 May 2012)");
  script_name("Microsoft Silverlight Code Execution Vulnerabilities (2681578) - Mac OS X");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2681578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50462");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53335");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2690729");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027048");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-034");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_ms_silverlight_detect_macosx.nasl");
  script_mandatory_keys("MS/Silverlight/MacOSX/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted file.");

  script_tag(name:"affected", value:"Microsoft Silverlight versions 4 and 5.");

  script_tag(name:"insight", value:"The flaws are due to an error exists when parsing TrueType fonts.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-034.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

slightVer = get_kb_item("MS/Silverlight/MacOSX/Ver");
if(!slightVer){
  exit(0);
}

if(version_in_range(version: slightVer, test_version:"4.0", test_version2:"4.1.10328")||
   version_in_range(version: slightVer, test_version:"5.0", test_version2:"5.1.10410")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
