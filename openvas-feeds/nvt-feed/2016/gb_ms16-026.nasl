# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807513");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-0121", "CVE-2016-0120");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-03-09 08:23:23 +0530 (Wed, 09 Mar 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Graphic Fonts Multiple Vulnerabilities (3143148)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-026.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to the Windows
  Adobe Type Manager Library improperly handles specially crafted OpenType
  fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code. Failed exploit attempts will result in
  a denial-of-service condition.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2012/R2

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3140735");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-026");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

userVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Atmfd.dll");
if(!userVer){
  exit(0);
}
## Win 8.1 and win2012R2
if(hotfix_check_sp(winVista:3, win2008:3, win7:2, win7x64:2, win2008r2:2,
                   win2012:1, win8_1:1, win8_1x64:1, win2012R2:1, win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:userVer, test_version:"5.1.2.247"))
  {
    report = 'File checked:     ' + sysPath + "\system32\Atmfd.dll" + '\n' +
             'File version:     ' + userVer  + '\n' +
             'Vulnerable range: Less than 5.1.2.247\n' ;
    security_message(data:report);
    exit(0);
  }
}
