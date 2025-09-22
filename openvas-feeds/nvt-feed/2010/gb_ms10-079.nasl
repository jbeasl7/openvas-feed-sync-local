# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902265");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-2747", "CVE-2010-2748", "CVE-2010-2750", "CVE-2010-3214",
                "CVE-2010-3215", "CVE-2010-3216", "CVE-2010-3217", "CVE-2010-3218",
                "CVE-2010-3219", "CVE-2010-3220", "CVE-2010-3221");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Word Remote Code Execution Vulnerabilities (2293194)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Prdts/Installed");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2328360");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2344993");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2344911");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2345043");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2345000");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2626");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted word document.");

  script_tag(name:"affected", value:"- Microsoft Word 2010

  - Microsoft Office Word Viewer

  - Microsoft Office Word 2002 Service Pack 3

  - Microsoft Office Word 2003 Service Pack 3

  - Microsoft Office Word 2007 Service Pack 2

  - Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats Service Pack 2");

  script_tag(name:"insight", value:"The flaws are due to:

  - An uninitialized pointer error when processing malformed data in a Word file

  - An improper boundary check when processing certain data in a Word file

  - An error when handling index values within a Word document

  - A stack overflow error when processing malformed data within a Word
  document

  - An error when handling return values, bookmarks, pointers while parsing
  a specially crafted Word

  - A heap overflow error when handling malformed records within a Word file

  - An error when handling indexes while parsing a specially crafted Word file");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-079.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-079");
  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

winwordVer = get_kb_item("SMB/Office/Word/Version");
if(winwordVer =~ "^1[0124]\.")
{
  if(version_in_range(version:winwordVer, test_version:"10.0", test_version2:"10.0.6865.0") ||
     version_in_range(version:winwordVer, test_version:"11.0", test_version2:"11.0.8327.0") ||
     version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6545.4999") ||
     version_in_range(version:winwordVer, test_version:"14.0", test_version2:"14.0.5120.4999"))
  {
    report = report_fixed_ver(installed_version:winwordVer, vulnerable_range:"10.0 - 10.0.6865.0, 11.0 - 11.0.8327.0, 12.0 - 12.0.6545.4999, 14.0 - 14.0.5120.4999");
    security_message(port:0, data:report);
    exit(0);
  }
}

wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
if(wordcnvVer =~ "^12\.")
{
  if(version_in_range(version:wordcnvVer, test_version:"12.0", test_version2:"12.0.6545.4999"))
  {
    report = report_fixed_ver(installed_version:wordcnvVer, vulnerable_range:"12.0 - 12.0.6545.4999");
    security_message(port:0, data:report);
    exit(0);
  }
}
