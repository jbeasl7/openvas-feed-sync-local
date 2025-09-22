# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806863");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-0051");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:10:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-02-10 10:51:05 +0530 (Wed, 10 Feb 2016)");
  script_name("Microsoft Windows WebDAV Elevation Of Privilege Vulnerability (3136041)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-016");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation
  of input in the Microsoft Web Distributed Authoring and Versioning (WebDAV).");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code with elevated permissions.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows Vista x32/x64 Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2

  - Microsoft Windows 7 x32/x64 Service Pack 1

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1

  - Microsoft Windows 10 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3136041");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3124280");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-016");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, win8:1,
                   win8x64:1, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Drivers\Mrxdav.sys");
if(!sysVer){
  exit(0);
}

if (sysVer =~ "^(6\.0\.6002\.1)"){
  Vulnerable_range = "Less than 6.0.6002.19576";
}
else if (sysVer =~ "^(6\.0\.6002\.2)"){
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23885";
}
else if (sysVer =~ "^(6\.1\.7601\.2)"){
  Vulnerable_range = "6.1.7601.23000 - 6.1.7601.23316";
}
else if (sysVer =~ "^(6\.1\.7601\.1)"){
  Vulnerable_range = "Less than 6.1.7601.19113";
}
else if (sysVer =~ "^(6\.2\.9200\.1)"){
  Vulnerable_range = "Less than 6.2.9200.17619";
}
else if (sysVer =~ "^(6\.2\.9200\.2)"){
  Vulnerable_range = "6.2.9200.21000 - 6.2.9200.21737";
}
else if (sysVer =~ "^(6\.3\.9600\.1)"){
  Vulnerable_range = "Less than 6.3.9600.18189";
}
else if (sysVer =~ "^(10\.0\.10240)"){
  Vulnerable_range = "Less than 10.0.10240.16683";
}
else if (sysVer =~ "^(10\.0\.10586)"){
  Vulnerable_range = "10.0.10586.0 - 10.0.10586.102";
}

if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.0.6002.19576")||
     version_in_range(version:sysVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23885")){
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7601.19113") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.23000", test_version2:"6.1.7601.23316")){
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.2.9200.17619") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21737")){
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.3.9600.18189")){
     VULN = TRUE ;
  }
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"10.0.10240.16683") ||
     version_in_range(version:sysVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.102")){
     VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\Drivers\Mrxdav.sys" + '\n' +
           'File version:     ' + sysVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
