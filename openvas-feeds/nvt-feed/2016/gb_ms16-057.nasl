# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807586");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-0179");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-05-11 08:26:35 +0530 (Wed, 11 May 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Shell Remote Code Execution Vulnerability (3156987)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-057.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists when windows Shell
  improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the affected application
  and failed attacks will cause denial-of-service conditions.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012 R2

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3156987");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-057");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

shelldllPath = smb_get_systemroot();
if(!shelldllPath){
  exit(0);
}

shelldllVer = fetch_file_version(sysPath:shelldllPath, file_name:"system32\Windows.ui.dll");
edgedllVer = fetch_file_version(sysPath:shelldllPath, file_name:"system32\Edgehtml.dll");
if(!shelldllVer && !edgedllVer){
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:shelldllVer, test_version:"6.3.9600.18302"))
  {
    Vulnerable_range = "Less than 6.3.9600.18302";
    VULN1 = TRUE ;
  }
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_in_range(version:edgedllVer, test_version:"11.0.10240.0", test_version2:"11.0.10240.16840"))
  {
    Vulnerable_range = "11.0.10240.0 - 11.0.10240.16840";
    VULN2 = TRUE;
  }
  else if(version_in_range(version:edgedllVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.305"))
  {
    VULN2 = TRUE;
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.305";
  }
}

if(VULN1)
{
  report = 'File checked:     ' + shelldllPath + "\System32\Windows.ui.dll" + '\n' +
           'File version:     ' + shelldllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
}

if(VULN2)
{
  report = 'File checked:     ' + shelldllPath + "\System32\Edgehtml.dll" + '\n' +
           'File version:     ' + edgedllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
}

