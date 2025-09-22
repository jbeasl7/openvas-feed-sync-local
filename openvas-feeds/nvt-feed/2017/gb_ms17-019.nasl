# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810813");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-0043");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-03-15 11:04:14 +0530 (Wed, 15 Mar 2017)");
  script_name("Microsoft Active Directory Federation Services Information Disclosure Vulnerability (4010320)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS17-019.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Windows Active Directory
  Federation Services (ADFS) honors XML External Entities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to read sensitive information about the target system.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2012/2012R2

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/4010320");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96628");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-019");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-019");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2008:3, win2008r2:2, win2008x64:3, win2012:1, win2012R2:1,
                   win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

winVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Win32k.sys");
if(!winVer){
  exit(0);
}

if(hotfix_check_sp(win2008r2:2) > 0)
{
  ## Presently GDR information is not available.
  if(winVer && version_is_less(version:winVer, test_version:"6.1.7601.23677"))
  {
    Vulnerable_range = "Less than 6.1.7601.23677";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2008:3, win2008x64:3) > 0)
{
    adfs = registry_key_exists(key:"SOFTWARE\Microsoft\ADFS");
    if(!adfs){
      exit(0);
    }

    dllVer = fetch_file_version(sysPath:sysPath, file_name:"\ADFS\Microsoft.identityserver.dll");
    if(!dllVer){
      exit(0);
    }

    if(version_is_less(version:dllVer, test_version:"7.0.6002.19742"))
    {
      Vulnerable_range = "Less than 7.0.6002.19742";
      VULN = TRUE ;
    }

    else if(version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.24066"))
    {
      Vulnerable_range = "7.0.6002.22000 - 7.0.6002.24066";
      VULN = TRUE ;
    }

    if(VULN)
    {
      report = 'File checked:     ' + sysPath + "\ADFS\Microsoft.identityserver.dll" + '\n' +
               'File version:     ' + dllVer + '\n' +
               'Vulnerable range: ' + Vulnerable_range + '\n' ;
      security_message(data:report);
      exit(0);
    }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(winVer && version_is_less(version:winVer, test_version:"6.2.9200.22099"))
  {
     Vulnerable_range = "Less than 6.2.9200.22099";
     VULN = TRUE ;
  }
}

## Win2012R2
else if(hotfix_check_sp(win2012R2:1) > 0)
{
  if(winVer && version_is_less(version:winVer, test_version:"6.3.9600.18603"))
  {
    Vulnerable_range = "Less than 6.3.9600.18603";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2016:1) > 0)
{
  if( winVer && version_in_range(version:winVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.593"))
  {
    Vulnerable_range = "10.0.14393.0 - 10.0.14393.593";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Win32k.sys" + '\n' +
           'File version:     ' + winVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
