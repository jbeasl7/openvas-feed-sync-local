# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902931");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-1885", "CVE-2012-1886", "CVE-2012-1887", "CVE-2012-2543");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-11-14 08:55:19 +0530 (Wed, 14 Nov 2012)");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2720184) - Mac OS X");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-076");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56425");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56426");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56430");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56431");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code
  with the privileges of the user running the affected application.");
  script_tag(name:"affected", value:"- Microsoft Office 2008 for Mac

  - Microsoft Office 2011 for Mac");
  script_tag(name:"insight", value:"- An error when processing the 'SerAuxErrBar' record can be exploited to
    cause a heap-based buffer overflow via a specially crafted file.

  - An input validation error can be exploited to corrupt memory via a
    specially crafted file.

  - A use-after-free error when processing the 'SST' record can be
    exploited via a specially crafted file.

  - An error when processing certain data structures can be exploited to
    cause a stack-based buffer overflow via a specially crafted file.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-076.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-076");
  exit(0);
}

include("version_func.inc");

offVer = get_kb_item("MS/Office/MacOSX/Ver");
if(!offVer){
  exit(0);
}

if(version_in_range(version:offVer, test_version:"12.0", test_version2:"12.3.4")||
   version_in_range(version:offVer, test_version:"14.0", test_version2:"14.2.4")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
