# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807301");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-0054");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:10:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-02-10 09:23:53 +0530 (Wed, 10 Feb 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Excel Remote Code Execution Vulnerability (3134226)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-015.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Microsoft Excel improperly handles while
  opening specially crafted Office file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Excel 2007 Service Pack 3 and prior

  - Microsoft Excel 2010 Service Pack 2 and prior

  - Microsoft Excel 2013 Service Pack 1 and prior

  - Microsoft Excel 2016 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114734");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114759");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114741");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-015");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms16-015");
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
    Vulnerable_range  =  "12 - 12.0.6743.4999";
  }
  else if(excelVer =~ "^14"){
    Vulnerable_range  =  "14 - 14.0.7166.4999";
  }
  else if(excelVer =~ "^15"){
   Vulnerable_range  =  "15 - 15.0.4797.0999";
  }
  else if(excelVer =~ "^16"){
   Vulnerable_range  =  "16 - 16.0.4339.0999";
  }

  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6743.4999") ||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.7166.4999") ||
     version_in_range(version:excelVer, test_version:"15.0", test_version2:"15.0.4797.0999") ||
     version_in_range(version:excelVer, test_version:"16.0", test_version2:"16.0.4339.0999"))
  {
    report = 'File checked:     ' + excelPath + "Excel.exe" + '\n' +
             'File version:     ' + excelVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
