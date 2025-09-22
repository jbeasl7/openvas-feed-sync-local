# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809344");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-7188");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:14:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-10-12 08:11:15 +0530 (Wed, 12 Oct 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Diagnostics Hub Privilege Elevation Vulnerability (3193229)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-125.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An elevation of privilege vulnerability exists
  in the Windows Diagnostics Hub Standard Collector Service when the Windows
  Diagnostics Hub Standard Collector Service fails to properly sanitize input.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code with elevated system privileges. An attacker could then
  install programs, view, change, or delete data, or create new accounts with
  full user rights.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3194798");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93359");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3192441");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3192440");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-125");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS16-125");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"11.0.10240.17146"))
  {
    Vulnerable_range = "Less than 11.0.10240.17146";
    VULN = TRUE ;
  }

  else if(version_in_range(version:sysVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.632"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.632";
    VULN = TRUE ;
  }
  else if(version_in_range(version:sysVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.320"))
  {
    Vulnerable_range = "11.0.14393.0 - 11.0.14393.320";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + sysVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
