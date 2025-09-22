# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902378");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-06-15 15:55:00 +0200 (Wed, 15 Jun 2011)");
  script_cve_id("CVE-2011-1272", "CVE-2011-1273", "CVE-2011-1274", "CVE-2011-1275",
                "CVE-2011-1276", "CVE-2011-1277", "CVE-2011-1278", "CVE-2011-1279");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Excel Remote Code Execution Vulnerabilities (2537146)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2541003");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48157");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48158");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48159");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48160");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48161");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48163");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48164");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2541025");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2541007");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2541015");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2523021");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-045");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code with
  the privileges of the user running the affected application.");

  script_tag(name:"affected", value:"- Microsoft Office Excel 2010

  - Microsoft Excel Viewer Service Pack 2

  - Microsoft Office Excel 2002 Service Pack 3

  - Microsoft Office Excel 2003 Service Pack 3

  - Microsoft Office Excel 2007 Service Pack 2");

  script_tag(name:"insight", value:"The flaws are caused by memory corruption, heap and integer overflows, buffer
  overwrite, out of bounds array access when handling the crafted Excel files.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-045.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^1[0124]\.0")
{
  if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6870.0") ||
     version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8334.0") ||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6557.4999") ||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.5138.4999"))
  {
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"10.0 - 10.0.6870.0, 11.0 - 11.0.8334.0, 12.0 - 12.0.6557.4999, 14.0 - 14.0.5138.4999");
    security_message(port:0, data:report);
    exit(0);
  }
}

excelVer = get_kb_item("SMB/Office/XLView/Version");
if(excelVer && excelVer =~ "^12\.0")
{
  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6557.4999")){
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"12.0 - 12.0.6557.4999");
    security_message(port:0, data:report);
  }
}
