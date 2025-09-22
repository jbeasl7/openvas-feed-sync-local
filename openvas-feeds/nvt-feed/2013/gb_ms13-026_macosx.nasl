# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903201");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-0095");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-03-13 11:30:32 +0530 (Wed, 13 Mar 2013)");
  script_name("Microsoft Office Outlook Information Disclosure Vulnerability (2813682) - Mac OS X");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/82400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58333");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-026");

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain access to potentially
  sensitive information and that may aid in further attacks.");

  script_tag(name:"affected", value:"- Microsoft Office 2008 on Mac OS X

  - Microsoft Office 2011 on Mac OS X");

  script_tag(name:"insight", value:"The flaw is due to Microsoft Outlook for Mac loading certain tags when
  previewing an HTML email, which can be exploited to load content from a
  remote server and confirm the existence of the targeted email accounts.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-026.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

offVer = get_kb_item("MS/Office/MacOSX/Ver");

if(!offVer || offVer !~ "^1[24]\."){
  exit(0);
}

if(version_in_range(version:offVer, test_version:"12.0", test_version2:"12.3.5")||
   version_in_range(version:offVer, test_version:"14.0", test_version2:"14.3.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
