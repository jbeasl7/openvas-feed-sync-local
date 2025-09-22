# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806864");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-0050");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-08 22:03:00 +0000 (Wed, 08 May 2019)");
  script_tag(name:"creation_date", value:"2016-02-10 08:17:05 +0530 (Wed, 10 Feb 2016)");
  script_name("Microsoft Windows NPS RADIUS Server Denial of Service Vulnerability (3133043)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-021");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper handling
  of a Remote Authentication Dial-In User Service (RADIUS) authentication
  request in Network Policy Server (NPS).");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to send specially crafted username strings to a Network Policy
  Server (NPS) causing a denial of service condition for RADIUS authentication
  on the NPS.");

  script_tag(name:"affected", value:"- Microsoft Windows server 2008 x32/x64 Edition Service Pack 2

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1

  - Microsoft Windows Server 2012/2012R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3133043");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-021");

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

if(hotfix_check_sp(win2012:1, win2012R2:1, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Iassam.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.2.9200.17623"))
  {
     Vulnerable_range = "Less than 6.2.9200.17623";
     VULN = TRUE ;
  }

  else if(version_in_range(version:dllVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21742"))
  {
     Vulnerable_range = "6.2.9200.21000 - 6.2.9200.21742";
     VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.3.9600.18191"))
  {
    Vulnerable_range = "Less than 6.3.9600.18191";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.6002.19578"))
  {
    Vulnerable_range = "Less than 6.3.9600.18191";
    VULN = TRUE ;
  }

  else if(version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23887"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23887";
    VULN = TRUE ;
  }
}

else if(hotfix_check_sp(win2008r2:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7601.19114"))
  {
    Vulnerable_range = "Less than 6.1.7601.19114";
    VULN = TRUE ;
  }

  else if(version_in_range(version:dllVer, test_version:"6.1.7601.23000", test_version2:"6.1.7601.23317"))
  {
    Vulnerable_range = "6.1.7601.23000 - 6.1.7601.23317";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\Iassam.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
