# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812827");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2018-0811", "CVE-2018-0813", "CVE-2018-0814", "CVE-2018-0886",
                "CVE-2018-0888", "CVE-2018-0889", "CVE-2018-0891", "CVE-2018-0894",
                "CVE-2018-0895", "CVE-2018-0896", "CVE-2018-0897", "CVE-2018-0898",
                "CVE-2018-0899", "CVE-2018-0900", "CVE-2018-0901", "CVE-2018-0904",
                "CVE-2018-0927", "CVE-2018-0929", "CVE-2018-0932", "CVE-2018-0935",
                "CVE-2018-0942", "CVE-2018-0816", "CVE-2018-0817", "CVE-2018-0868",
                "CVE-2018-0878", "CVE-2018-0881", "CVE-2018-0883", "CVE-2018-0885");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-03-14 09:46:08 +0530 (Wed, 14 Mar 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4088876)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4088876");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - When Windows Hyper-V on a host operating system fails to properly validate
    input from an authenticated user on a guest operating system.

  - The way that the scripting engine handles objects in memory in Internet
    Explorer.

  - When Microsoft Hyper-V Network Switch on a host server fails to properly
    validate input from a privileged user on a guest operating system.

  - The Credential Security Support Provider protocol (CredSSP).

  - When the Microsoft Video Control mishandles objects in memory.

  - When Windows Shell does not properly validate file copy destinations.

  - When Internet Explorer improperly handles objects in memory.

  - When Internet Explorer fails a check, allowing sandbox escape.

  - The Windows kernel that could allow an attacker to retrieve information
    that could lead to a Kernel Address Space Layout Randomization (ASLR) bypass.

  - The Windows Installer when the Windows Installer fails to properly sanitize
    input leading to an insecure library loading behavior.

  - The Windows kernel improperly initializes objects in memory.

  - When Windows Remote Assistance incorrectly processes XML External Entities
    (XXE).

  - The way that the Windows Graphics Device Interface (GDI) handles objects in
    memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to gain access to information, crash server and run arbitrary code in system
  mode.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4088876");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103232");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103250");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103251");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103265");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103262");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103295");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103309");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103231");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103238");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103240");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103241");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103242");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103243");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103244");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103245");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103246");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103310");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103299");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103307");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103298");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103312");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103248");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103249");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103236");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103230");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103256");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103259");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103261");
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

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"urlmon.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"11.0.9600.18939"))
{
  report = report_fixed_ver(file_checked:sysPath + "\urlmon.dll",
  file_version:fileVer, vulnerable_range:"Less than 11.0.9600.18939");
  security_message(data:report);
  exit(0);
}
exit(0);
