# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811746");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-0161", "CVE-2017-8719", "CVE-2017-8720", "CVE-2017-8628",
                "CVE-2017-8733", "CVE-2017-8736", "CVE-2017-8675", "CVE-2017-8676",
                "CVE-2017-8741", "CVE-2017-8677", "CVE-2017-8678", "CVE-2017-8747",
                "CVE-2017-8748", "CVE-2017-8679", "CVE-2017-8680", "CVE-2017-8681",
                "CVE-2017-8749", "CVE-2017-8750", "CVE-2017-8682", "CVE-2017-8683",
                "CVE-2017-8684", "CVE-2017-8685", "CVE-2017-8687", "CVE-2017-8688",
                "CVE-2017-8696", "CVE-2017-8699", "CVE-2017-8707", "CVE-2017-8708",
                "CVE-2017-8709", "CVE-2017-8710", "CVE-2017-8695");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-10 19:58:00 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-13 09:34:11 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4038777)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4038777");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error when Windows Hyper-V on a host operating system fails to properly
    validate input from an authenticated user on a guest operating system.

  - An issue when the Windows kernel fails to properly initialize a memory address.

  - An error when the Windows kernel improperly handles objects in memory.

  - An error in Microsoft's implementation of the Bluetooth stack.

  - An error in the way that Microsoft browser JavaScript engines render content when
    handling objects in memory.

  - An error when Windows Uniscribe improperly discloses the contents of its memory.

  - An error due to the way Windows Uniscribe handles objects in memory.

  - An error when Microsoft browsers improperly access objects in memory.

  - An error when Internet Explorer improperly handles specific HTML content.

  - An error in Microsoft browsers due to improper parent domain verification in
    certain functionality.

  - An error in the way that the Windows Graphics Device Interface (GDI) handles
    objects in memory, allowing an attacker to retrieve information from a targeted
    system.

  - An error when the Windows GDI+ component improperly discloses kernel memory
    addresses.

  - An error in Windows when the Windows kernel-mode driver fails to properly handle
    objects in memory.

  - An error when Windows Shell does not properly validate file copy destinations.

  - An error in Windows kernel.

  - An error when the Windows font library improperly handles specially crafted
    embedded fonts.

  - An error in the Microsoft Common Console Document.

  - An error in Windows when the Win32k component fails to properly handle objects in
    memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to gain access to potentially sensitive information, perform a
  man-in-the-middle attack and force a user's computer to unknowingly route
  traffic through the attacker's computer, execute arbitrary code on the target,
  embed an ActiveX control marked safe for initialization, take complete control
  of the affected system and read arbitrary files on the affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4038777");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100728");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100744");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100737");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100743");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100752");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100764");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100767");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100769");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100766");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100720");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100727");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100771");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100772");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100781");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100782");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100724");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100736");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100756");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100780");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100790");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100791");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100792");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100793");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100773");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

fileVer = fetch_file_version(sysPath:sysPath, file_name:"win32spl.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.23889"))
{
  report = 'File checked:     ' + sysPath + "\win32spl.dll" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range:  Less than 6.1.7601.23889\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
