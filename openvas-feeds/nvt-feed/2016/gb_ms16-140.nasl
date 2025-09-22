# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809802");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-7247");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:14:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-11-09 08:16:52 +0530 (Wed, 09 Nov 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Boot Manager Security Feature Bypass Vulnerability (3193479)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-140.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to windows secure boot
  improperly loads a boot policy that is affected by the vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to disable code integrity checks, allowing test-signed executables
  and drivers to be loaded onto a target device.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3193479");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94058");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-140");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-140");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1,
                   win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

oleVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Ole32.dll");
if(!oleVer){
  exit(0);
}

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:oleVer, test_version:"6.3.9600.18508"))
  {
    Vulnerable_range = "Less than 6.3.9600.18508";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:oleVer, test_version:"6.2.9200.22005"))
  {
    Vulnerable_range = "Less than 6.2.9200.22005";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:oleVer, test_version:"10.0.10240.17184"))
  {
    Vulnerable_range = "Less than 10.0.10240.17184";
    VULN = TRUE ;
  }
  else if(version_in_range(version:oleVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.671"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.671";
    VULN = TRUE ;
  }
  else if(version_in_range(version:oleVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.446"))
  {
    Vulnerable_range = "10.0.14393.0 - 10.0.14393.446";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Ole32.dll" + '\n' +
           'File version:     ' + oleVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
