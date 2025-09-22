# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902410");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0097", "CVE-2011-0098", "CVE-2011-0101", "CVE-2011-0103",
                "CVE-2011-0104", "CVE-2011-0105", "CVE-2011-0978", "CVE-2011-0979",
                "CVE-2011-0980");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Excel Remote Code Execution Vulnerabilities (2489279)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2466146");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2466169");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2502786");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2466158");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0940");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-021");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a malicious Excel file.");
  script_tag(name:"affected", value:"- Microsoft Excel Viewer Service Pack 2

  - Microsoft Office Excel 2002 Service Pack 3

  - Microsoft Office Excel 2003 Service Pack 3

  - Microsoft Office Excel 2007 Service Pack 2

  - Microsoft Office Excel 2010");

  script_tag(name:"insight", value:"The flaws are caused by memory corruption, heap and integer overflows, buffer
  overwrite, array indexing, and dangling pointers when parsing malformed data or
  records within Excel documents, which could be exploited by attackers to execute
  arbitrary code by tricking a user into opening a specially crafted Excel file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-021.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^1[0124]\.0")
{
  if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6868.0") ||
     version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8331.0") ||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6550.5003") ||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.5130.5002"))
  {
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"10.0 - 10.0.6868.0, 11.0 - 11.0.8331.0, 12.0 - 12.0.6550.5003, 14.0 - 14.0.5130.5002");
    security_message(port:0, data:report);
    exit(0);
  }
}

excelVer = get_kb_item("SMB/Office/XLView/Version");
if(excelVer && excelVer =~ "^12\.0")
{
  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6550.5003")){
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"12.0 - 12.0.6550.5003");
    security_message(port:0, data:report);
  }
}
