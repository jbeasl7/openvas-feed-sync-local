# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807517");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-0134");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-03-09 09:58:26 +0530 (Wed, 09 Mar 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Outlook Remote Code Execution Vulnerability (3141806)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-029.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to the Office software
  fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow a to execute
  arbitrary code in the context of the current user and to take control of the
  affected system.");

  script_tag(name:"affected", value:"- Microsoft Outlook 2007 Service Pack 3 and prior

  - Microsoft Outlook 2010 Service Pack 2 and prior

  - Microsoft Outlook 2013 Service Pack 1 and prior

  - Microsoft Outlook 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2880510");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114883");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-029");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/Outlook/Version");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

outlookVer = get_kb_item("SMB/Office/Outlook/Version");

if(!outlookVer || outlookVer !~ "^1[2456]\."){
  exit(0);
}

## Office outlook
outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OUTLOOK.EXE", item:"Path");
if(outlookFile)
{
  outlookVer = fetch_file_version(sysPath:outlookFile, file_name:"outlook.exe");
  if(outlookVer)
  {
    if(version_in_range(version:outlookVer, test_version:"12.0", test_version2:"12.0.6744.4999"))
    {
      Vulnerable_range = "12.0 - 12.0.6744.4999";
      VULN = TRUE ;
    }
    else if(version_in_range(version:outlookVer, test_version:"14.0", test_version2:"14.0.7167.4999"))
    {
      Vulnerable_range = "14.0 - 14.0.7167.4999";
      VULN = TRUE ;
    }
    else if(version_in_range(version:outlookVer, test_version:"15.0", test_version2:"15.0.4805.0999"))
    {
      Vulnerable_range = "15.0 - 15.0.4805.0999";
      VULN = TRUE ;
    }
    else if(version_in_range(version:outlookVer, test_version:"16.0", test_version2:"16.0.4351.0999"))
    {
      Vulnerable_range = "16.0 - 16.0.4351.0999";
      VULN = TRUE ;
    }
  }
}

if(VULN)
{
  report = 'File checked:     ' +  outlookFile + "\outlook.exe" + '\n' +
           'File version:     ' +  outlookVer  + '\n' +
           'Vulnerable range: ' +  Vulnerable_range + '\n' ;

  security_message(data:report);
  exit(0);
}
