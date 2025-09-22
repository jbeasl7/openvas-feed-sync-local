# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902930");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-1885", "CVE-2012-1886", "CVE-2012-1887", "CVE-2012-2543");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-11-14 08:46:19 +0530 (Wed, 14 Nov 2012)");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2720184)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687481");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56425");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56426");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56430");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56431");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687307");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687313");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687311");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2597126");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-076");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version", "MS/Office/Ver", "SMB/Office/XLView/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code
  with the privileges of the user running the affected application.");

  script_tag(name:"affected", value:"- Microsoft Excel Viewer

  - Microsoft Excel 2003 Service Pack 3

  - Microsoft Excel 2010 Service Pack 1 and prior

  - Microsoft Office 2010 Service Pack 1 and prior

  - Microsoft Excel 2007 Service Pack 2 and Service Pack 3

  - Microsoft Office 2007 Service Pack 2 and Service Pack 3

  - Microsoft Office Compatibility Pack Service Pack 2 and Service Pack 3");

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

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^1[124]\.")
{
  if(version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8346") ||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6665.5002") ||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.6126.5002"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## Microsoft Office Excel Viewer 2007
excelviewVer = get_kb_item("SMB/Office/XLView/Version");
if(excelviewVer && excelviewVer =~ "^12\.")
{
  if(version_in_range(version:excelviewVer, test_version:"12.0", test_version2:"12.0.6665.5002"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

cmptPckVer = get_kb_item("SMB/Office/ComptPack/Version");
if(cmptPckVer && cmptPckVer =~ "^1[24]\.")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer && xlcnvVer =~ "^1[24]\.")
  {
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6665.5002") ||
       version_in_range(version:xlcnvVer, test_version:"14.0", test_version2:"14.0.6126.5002")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
