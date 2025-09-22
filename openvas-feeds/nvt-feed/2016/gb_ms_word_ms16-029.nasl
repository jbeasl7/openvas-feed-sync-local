# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806899");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-0021", "CVE-2016-0057", "CVE-2016-0134");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:10:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-03-09 13:44:08 +0530 (Wed, 09 Mar 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Word Remote Code Execution Vulnerabilities (3141806)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-029");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as Office software fails
  to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Word 2007 Service Pack 3 and prior

  - Microsoft Word 2010 Service Pack 2 and prior

  - Microsoft Word 2013 Service Pack 1 and prior

  - Microsoft Word 2016 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114901");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114878");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114824");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-029");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms16-029");
  exit(0);
}


include("version_func.inc");

##word 2007, 2010, 2013, 2016
exeVer = get_kb_item("SMB/Office/Word/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Word/Install/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer && exeVer =~ "^(12|14|15|16).*")
{
  if(exeVer =~ "^12"){
    Vulnerable_range  =  "12 - 12.0.6745.4999";
  }
  else if(exeVer =~ "^14"){
    Vulnerable_range  =  "14 - 14.0.7167.5000";
  }
  else if(exeVer =~ "^15"){
    Vulnerable_range  =  "15 - 15.0.4805.1000";
  }
  else if(exeVer =~ "^16"){
    Vulnerable_range  =  "16 - 16.0.4351.1000";
  }

  if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6745.4999") ||
     version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7167.5000") ||
     version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4805.1000") ||
     version_in_range(version:exeVer, test_version:"16.0", test_version2:"16.0.4351.1000"))
  {
     report = 'File checked:     ' + exePath + "winword.exe"  + '\n' +
              'File version:     ' + exeVer  + '\n' +
              'Vulnerable range: ' + Vulnerable_range + '\n' ;
     security_message(data:report);
     exit(0);
  }
}
