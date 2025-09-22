# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810708");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-0006", "CVE-2017-0027", "CVE-2017-0020", "CVE-2017-0052");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-03-15 13:18:25 +0530 (Wed, 15 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Excel Multiple Vulnerabilities (4013241)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS17-014.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as

  - Microsoft Office improperly handles input.

  - Microsoft Office software reads out of bound memory.

  - Microsoft Office software improperly handles the parsing of file formats.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and gain
  access to potentially sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Excel 2007 Service Pack 3

  - Microsoft Excel 2010 Service Pack 2

  - Microsoft Excel 2013 Service Pack 1

  - Microsoft Excel 2016 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4013241");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96740");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96043");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96741");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3178676");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3178690");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3172542");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3178673");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms17-014");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(!excelVer){
  exit(0);
}

excelPath = get_kb_item("SMB/Office/Excel/Install/Path");
if(!excelPath){
   excelPath = "Unable to fetch the install path";
}

if(excelVer =~ "^(12|14|15|16)\..*")
{
  if(excelVer =~ "^12"){
    Vulnerable_range  =  "12 - 12.0.6765.4999";
  }
  else if(excelVer =~ "^14"){
    Vulnerable_range  =  "14 - 14.0.7179.4999";
  }
  else if(excelVer =~ "^15"){
    Vulnerable_range  =  "15 - 15.0.4911.0999";
  }
  else if(excelVer =~ "^16"){
    Vulnerable_range  =  "16 - 16.0.4510.0999";
  }

  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6765.4999")||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.7179.4999")||
     version_in_range(version:excelVer, test_version:"15.0", test_version2:"15.0.4911.0999")||
     version_in_range(version:excelVer, test_version:"16.0", test_version2:"16.0.4510.0999"))
  {
    report = 'File checked:     ' + excelPath + "Excel.exe" + '\n' +
             'File version:     ' + excelVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
