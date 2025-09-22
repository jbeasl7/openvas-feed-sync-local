# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900887");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-11-11 19:07:38 +0100 (Wed, 11 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:18:57 +0000 (Tue, 16 Jul 2024)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2009-3127", "CVE-2009-3128", "CVE-2009-3129", "CVE-2009-3130",
                "CVE-2009-3131", "CVE-2009-3132", "CVE-2009-3133", "CVE-2009-3134");
  script_name("Microsoft Office Excel Multiple Vulnerabilities (972652)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Prdts/Installed");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/972652");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36908");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36909");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36911");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36912");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36943");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36944");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36945");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36946");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-067");

  script_tag(name:"impact", value:"Successful exploitation could execute arbitrary code on the remote system
  and corrupt memory, buffer overflow via a specially crafted Excel file.");

  script_tag(name:"affected", value:"- Microsoft Excel Viewer 2003/2007

  - Microsoft Office Excel 2002/2003/2007

  - Microsoft Office Compatibility Pack for Word, Excel, PowerPoint 2007 File Formats SP 1/2");

  script_tag(name:"insight", value:"- An error in the parsing of Excel spreadsheets can be exploited to corrupt
    memory via a specially crafted Excel file.

  - An error in the processing of certain record objects can be
    exploited to corrupt memory via a specially crafted Excel file.

  - Another error in the processing of certain record objects can be
    exploited to corrupt memory via a specially crafted Excel file.

  - An error in the processing of Binary File Format (BIFF) records
    can be exploited to cause a heap-based buffer overflow via a specially
    crafted Excel file.

  - An error in the handling of formulas embedded inside a cell can
    be exploited to corrupt memory via a specially crafted Excel file.

  - An error when loading Excel formulas can be exploited to corrupt
    a pointer when a specially crafted Excel file is being opened.

  - An error when loading Excel records can be exploited to corrupt
    memory via a specially crafted Excel file.

  - An error when processing Excel record objects can be exploited
    via a specially crafted Excel file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-067.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^1[0-2]\.")
{
  if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6855.9")||
     version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8315.9")||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6514.4999"))
  {
    report = report_fixed_ver(installed_version:excelVer, vulnerable_range:"10.0 - 10.0.6855.9, 11.0 - 11.0.8315.9, 12.0 - 12.0.6514.4999");
    security_message(port:0, data:report);
    exit(0);
  }
}

cmptpVer = get_kb_item("SMB/Office/ComptPack/Version");
if(cmptpVer =~ "^12\.")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer =~ "^12\.")
  {
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6514.4999"))
    {
      report = report_fixed_ver(installed_version:xlcnvVer, vulnerable_range:"12.0 - 12.0.6514.4999");
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

xlviewVer = get_kb_item("SMB/Office/XLView/Version");
if(xlviewVer =~ "^1[12]\.")
{
  if(version_in_range(version:xlviewVer, test_version:"11.0", test_version2:"11.0.8312.9") ||
     version_in_range(version:xlviewVer, test_version:"12.0", test_version2:"12.0.6514.4999")){
    report = report_fixed_ver(installed_version:xlviewVer, vulnerable_range:"11.0 - 11.0.8312.9, 12.0 - 12.0.6514.4999");
    security_message(port:0, data:report);
  }
}
