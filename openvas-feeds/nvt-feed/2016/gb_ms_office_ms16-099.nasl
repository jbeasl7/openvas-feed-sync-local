# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807872");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-3313", "CVE-2016-3318", "CVE-2016-3317");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-08-10 11:22:55 +0530 (Wed, 10 Aug 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Suite Remote Code Execution Vulnerabilities (3177451)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-099.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as office software
  fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Office 2007 Service Pack 3

  - Microsoft Office 2010 Service Pack 2

  - Microsoft Office 2013 Service Pack 1

  - Microsoft Office 2016 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114442");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92289");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92308");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92303");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114893");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115415");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114400");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115468");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114869");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114340");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115427");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-099");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## MS Office
offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!path){
  exit(0);
}

## Microsoft Office 2007
## Microsoft Office 2010
## Microsoft Office 2013
## Microsoft Office 2016
if(offVer =~ "^(12|14)\..*")
{
  filePath = path + "\Microsoft Shared\GRPHFLT";

  fileVer1 = fetch_file_version(sysPath:filePath, file_name:"pictim32.flt");
  if(fileVer1)
  {
    if(fileVer1 =~ "^2006")
    {
      if(version_in_range(version:fileVer1, test_version:"2006", test_version2:"2006.1200.4518.1004"))
      {
        VULN1 = TRUE;
        Vulnerable_range1 = "2006 - 2006.1200.4518.1004";
      }
      else if(version_in_range(version:fileVer1, test_version:"2006.1200.6000", test_version2:"2006.1200.6753.4999"))
      {
        VULN1 = TRUE;
        Vulnerable_range1 = "2006.1200.6000 - 2006.1200.6753.4999";
      }
    }

    else if(fileVer1 =~ "^2010")
    {
      if(version_in_range(version:fileVer1, test_version:"2010", test_version2:"2010.1400.4740.0999"))
      {
        VULN1 = TRUE;
        Vulnerable_range1 = "2010 - 2010.1400.4740.0999";
      }
      else if(version_in_range(version:fileVer1, test_version:"2010.1400.7000", test_version2:"2010.1400.7006.0999"))
      {
        VULN1 = TRUE;
        Vulnerable_range1 = "2010.1400.7000 - 2010.1400.7006.0999";
      }
    }
  }
  if(VULN1)
  {
    report = 'File checked:     ' + filePath + "\pictim32.flt" + '\n' +
             'File version:     ' + fileVer1  + '\n' +
             'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
    security_message(data:report);
  }
}

if(offVer =~ "^15\..*")
{
  filePath2 = path + "\Microsoft Shared\TextConv";

  fileVer2 = fetch_file_version(sysPath:filePath2, file_name:"wpequ532.dll");
  if(fileVer2 =~ "^2012")
  {
    if(version_in_range(version:fileVer2, test_version:"2012", test_version2:"2012.1500.4454.0999"))
    {
      report = 'File checked:     ' + filePath2 + "\wpequ532.dll" + '\n' +
               'File version:     ' + fileVer2  + '\n' +
               'Vulnerable range: ' + "2012 - 2012.1500.4454.0999" + '\n' ;
      security_message(data:report);
    }
  }
}

##https://support.microsoft.com/en-us/kb/3115468
##File not available

if(offVer =~ "^(12|14|15|16)\..*")
{
  foreach offsubver (make_list("Office12", "Office15", "Office14", "Office16"))
  {
    offPath = path + "\Microsoft Shared\" + offsubver;
    offexeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");

    if(offexeVer)
    {
      if(offexeVer =~ "^12"){
        Vulnerable_range3  =  "12.0 - 12.0.6754.4999";
      }
      else if(offexeVer =~ "^14"){
        Vulnerable_range3  =  "14 - 14.0.7172.4999";
      }
      else if(offexeVer =~ "^15"){
        Vulnerable_range3  =  "15 - 15.0.4849.0999";
      }
      else if(offexeVer =~ "^16"){
        Vulnerable_range3  =  "16 - 16.0.4417.0999";
      }

      if(version_in_range(version:offexeVer, test_version:"12.0", test_version2:"12.0.6754.4999") ||
         version_in_range(version:offexeVer, test_version:"14.0", test_version2:"14.0.7172.4999") ||
         version_in_range(version:offexeVer, test_version:"15.0", test_version2:"15.0.4849.0999") ||
         version_in_range(version:offexeVer, test_version:"16.0", test_version2:"16.0.4417.0999"))
      {
        report = 'File checked:     ' + offPath + "\Mso.dll" + '\n' +
                 'File version:     ' + offexeVer  + '\n' +
                 'Vulnerable range: ' + Vulnerable_range3 + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}
