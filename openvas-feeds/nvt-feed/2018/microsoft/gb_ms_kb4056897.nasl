# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812384");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2018-0741", "CVE-2018-0747", "CVE-2018-0748", "CVE-2018-0749",
                "CVE-2018-0750", "CVE-2018-0754", "CVE-2018-0788", "CVE-2017-5753",
                "CVE-2017-5715", "CVE-2017-5754");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-01-04 15:14:57 +0530 (Thu, 04 Jan 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4056897)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4056897");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple errors in Windows Adobe Type Manager Font Driver (ATMFD.dll) when
    it fails to properly handle objects in memory.

  - An error in the Windows GDI component which improperly discloses kernel
    memory addresses.

  - An error in the Microsoft Server Message Block (SMB) Server when an attacker
    with valid credentials attempts to open a specially crafted file over the SMB
    protocol on the same machine.

  - An error in the way that the Windows Kernel API enforces permissions.

  - An error in the Windows kernel that could allow an attacker to retrieve
    information that could lead to a Kernel Address Space Layout Randomization
    (ASLR) bypass.

  - An error in the way that the Color Management Module (ICM32.dll) handles
    objects in memory.

  - Multiple errors leading to 'speculative execution side-channel attacks' that
    affect many modern processors and operating systems including Intel, AMD, and ARM.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and take control of an affected system, elevate their
  user rights, gain access to sensitive data, bypass certain security checks,
  impersonate processes, interject cross-process communication, interrupt system
  functionality and conduct bounds check bypass, branch target injection, rogue
  data cache load.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4056897");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"Advapi32.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.24000"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Advapi32.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.24000");
  security_message(data:report);
  exit(0);
}
exit(0);
