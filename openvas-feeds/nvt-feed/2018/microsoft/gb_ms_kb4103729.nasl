# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813353");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2018-4944");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 20:16:00 +0000 (Thu, 07 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-05-09 12:25:07 +0530 (Wed, 09 May 2018)");
  script_name("Adobe Flash Security Update (KB4103729)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4103729");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a type confusion
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1703 x32/x64

  - Microsoft Windows 10 Version 1803 for 32-bit Systems

  - Microsoft Windows 10 Version 1803 for x64-based Systems

  - Microsoft Windows 10 Version 1709 for 32-bit Systems

  - Microsoft Windows 10 Version 1709 for 64-based Systems

  - Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems

  - Microsoft Windows 10 Version 1607 x32/x64

  - Microsoft Windows Server 2016

  - Microsoft Windows 8.1 for 32-bit/x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4103729");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1, win8_1:1, win8_1x64:1, win2012:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"flashplayerapp.exe");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"29.0.0.171"))
{
  report = report_fixed_ver(file_checked:sysPath + "\flashplayerapp.exe",
                            file_version:fileVer, vulnerable_range:"Less than 29.0.0.171");
  security_message(data:report);
  exit(0);
}

exit(99);
