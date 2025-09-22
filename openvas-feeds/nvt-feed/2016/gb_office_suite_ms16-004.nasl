# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806188");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-0010", "CVE-2016-0012");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:10:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-01-13 10:25:01 +0530 (Wed, 13 Jan 2016)");
  script_name("Microsoft Office Suite Remote Code Execution Vulnerabilities (3124585)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_office_detection_900025.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3124585");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114486");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114553");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-004");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms16-004");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-004.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist when,

  - The Office software improperly handles objects in memory while parsing
    specially crafted Office files.

  - The Office software fails to properly handle rich text format files in
    memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Office 2007 Service Pack 3 and prior

  - Microsoft Office 2010 Service Pack 2 and prior

  - Microsoft Office 2013 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

## MS Office 2007,2010, 2015
if(offVer =~ "^1[245].*")
{
  InsPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(InsPath)
  {
    foreach offsubver (make_list("Office12", "Office15", "Office14"))
    {
      offPath = InsPath + "\Microsoft Shared\" + offsubver;
      exeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");
      if(exeVer)
      {
        if(exeVer =~ "^12"){
          Vulnerable_range  =  "12.0 - 12.0.6741.4999";
        }
        else if(exeVer =~ "^14"){
          Vulnerable_range  =  "14 - 14.0.7165.4999";
        }
        else if(exeVer =~ "^15"){
          Vulnerable_range  =  "15 - 15.0.4787.1001";
        }
      }

      ## For office 2010 Wwlibcxm.dll is mentioned and it is not available so ignoring
      if(exeVer)
      {
        if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6741.4999") ||
           version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7165.4999") ||
           version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4787.1001"))
        {

          report = 'File checked:     ' + offPath + "\mso.dll" + '\n' +
                   'File version:     ' + exeVer  + '\n' +
                   'Vulnerable range: ' + Vulnerable_range + '\n' ;
          security_message(data:report);
          exit(0);
        }
      }
    }
  }
}

## MS Office 2013
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mscomctl.Ocx");
if(sysVer)
{
  if(offVer =~ "^1[45].*")
  {
    if(version_is_less(version:sysVer, test_version:"6.01.98.46"))
    {
      report = "File checked:     " + sysPath + "\system32\Mscomctl.Ocx\n" +
               "File version:     " + sysVer  + "\n" +
               "Vulnerable range:  Less than  6.01.98.46\n" ;
      security_message(data:report);
      exit(0);
    }
  }
}
