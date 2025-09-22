# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902911");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-0183");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-05-09 09:26:38 +0530 (Wed, 09 May 2012)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerability (2680352)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Prdts/Installed");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2596880");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53344");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2598332");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2596917");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-029");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted word document.");

  script_tag(name:"affected", value:"- Microsoft Office Word 2003 Service Pack 3

  - Microsoft Office Word 2007 Service Pack 2

  - Microsoft Office Word 2007 Service Pack 3

  - Microsoft Office Compatibility Pack for File Formats Service Pack 2");

  script_tag(name:"insight", value:"The flaw is due to an error when parsing Rich Text Format (RTF)data
  and can be exploited to corrupt memory.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-029.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

winwordVer = get_kb_item("SMB/Office/Word/Version");
if(winwordVer =~ "^1[12]\.")
{
  if(version_in_range(version:winwordVer, test_version:"11.0", test_version2:"11.0.8344") ||
     version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6661.4999"))
  {
    report = report_fixed_ver(installed_version:winwordVer, vulnerable_range:"11.0 - 11.0.8344, 12.0 - 12.0.6661.4999");
    security_message(port:0, data:report);
    exit(0);
  }
}

wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
if(wordcnvVer =~ "^12\.")
{
  if(version_in_range(version:wordcnvVer, test_version:"12.0", test_version2:"12.0.6661.4999"))
  {
    report = report_fixed_ver(installed_version:wordcnvVer, vulnerable_range:"12.0 - 12.0.6661.4999");
    security_message(port:0, data:report);
    exit(0);
  }
}
