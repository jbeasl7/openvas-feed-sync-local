# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810706");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-0029", "CVE-2017-0019", "CVE-2017-0030", "CVE-2017-0031",
                "CVE-2017-0053", "CVE-2017-0105");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-03-15 12:39:37 +0530 (Wed, 15 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Word Multiple Vulnerabilities (4013241)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS17-014");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Office software fails to properly handle objects in memory.

  - Microsoft Office fails to properly handle specially crafted file.

  - Microsoft Office software reads out of bound memory due to an uninitialized
    variable.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to gain access to potentially sensitive information, run arbitrary
  code in the context of the current user or cause Office to stop responding.");

  script_tag(name:"affected", value:"- Microsoft Word 2016

  - Microsoft Word 2007 Service Pack 3

  - Microsoft Word 2010 Service Pack 2

  - Microsoft Word 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3178683");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96042");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96052");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96745");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96746");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3178687");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3172464");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3178674");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms17-014");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  exit(0);
}


include("version_func.inc");

## Word 2007, 2010, 2013. 2016
exeVer = get_kb_item("SMB/Office/Word/Version");
exePath = get_kb_item("SMB/Office/Word/Install/Path");

if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer && exeVer =~ "^(12|14|15|16).*")
{
  if(exeVer =~ "^12"){
    Vulnerable_range  =  "12 - 12.0.6765.4999";
  }
  else if(exeVer =~ "^14"){
    Vulnerable_range  =  "14 - 14.0.7179.4999";
  }
  else if(exeVer =~ "^15"){
    Vulnerable_range  =  "15 - 15.0.4911.999";
  }
  else if(exeVer =~ "^16"){
    Vulnerable_range  =  "16 - 16.0.4510.999";
  }

  if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6765.4999") ||
     version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7179.4999") ||
     version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4911.999") ||
     version_in_range(version:exeVer, test_version:"16.0", test_version2:"16.0.4510.999"))
  {
     report = 'File checked:     ' + exePath + "winword.exe"  + '\n' +
              'File version:     ' + exeVer  + '\n' +
              'Vulnerable range: ' + Vulnerable_range + '\n' ;
     security_message(data:report);
     exit(0);
  }
}
