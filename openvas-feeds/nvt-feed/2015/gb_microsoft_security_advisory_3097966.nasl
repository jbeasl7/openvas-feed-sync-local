# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806092");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-10-15 10:51:26 +0530 (Thu, 15 Oct 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Inadvertently Disclosed Digital Certificates Advisory (3097966)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory (3097966).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An update is available that modifies the
  Code Integrity component in Windows to extend trust removal for the
  certificates to also preclude kernel-mode code signing.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct spoofing attack.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2012 R2

  - Microsoft Windows 8 x32/x64

  - Microsoft Windows Server 2012

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3097966");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/3097966");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8:1, winVista:3,
                   win8x64:1, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,
                   win2008:3) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\ci.dll");
if(!dllVer){
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.6002.18005"))
  {
    Vulnerable_range = "Version Less than - 6.0.6002.18005";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7601.18519"))
  {
    Vulnerable_range = "Version Less than - 6.1.7601.18519";
    VULN = TRUE ;
  }

  else if(version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22729"))
  {
    Vulnerable_range = "6.1.7601.22000 - 6.1.7601.22729";
    VULN = TRUE ;
  }
}

## Win 8 and 2012
else if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.2.9200.16569"))
  {
    Vulnerable_range = "Version Less than - 6.2.9200.16569";
    VULN = TRUE ;
  }

 else if(version_in_range(version:dllVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20678"))
  {
    Vulnerable_range = "6.2.9200.20000 - 6.2.9200.20678";
    VULN = TRUE ;
  }
}

## Win 8.1 and 2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.3.9600.17550"))
  {
    Vulnerable_range = "Version Less than - 6.3.9600.17550";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\ci.dll" + "\n" +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
