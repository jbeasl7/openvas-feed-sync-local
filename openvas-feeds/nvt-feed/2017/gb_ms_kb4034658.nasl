# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811277");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-0174", "CVE-2017-0250", "CVE-2017-0293", "CVE-2017-8503",
                "CVE-2017-8591", "CVE-2017-8593", "CVE-2017-8620", "CVE-2017-8623",
                "CVE-2017-8624", "CVE-2017-8625", "CVE-2017-8633", "CVE-2017-8635",
                "CVE-2017-8636", "CVE-2017-8639", "CVE-2017-8640", "CVE-2017-8641",
                "CVE-2017-8644", "CVE-2017-8645", "CVE-2017-8646", "CVE-2017-8652",
                "CVE-2017-8653", "CVE-2017-8655", "CVE-2017-8656", "CVE-2017-8657",
                "CVE-2017-8661", "CVE-2017-8664", "CVE-2017-8666", "CVE-2017-8672",
                "CVE-2017-8669", "CVE-2017-8670", "CVE-2017-8671");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-20 18:55:00 +0000 (Wed, 20 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-08-09 08:31:54 +0530 (Wed, 09 Aug 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4034658)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4034658");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the way JavaScript engines render when handling objects in memory
    in Microsoft browsers.

  - An error when Windows Search handles objects in memory.

  - An error when Microsoft Hyper-V Network Switch on a host server fails to
    properly validate input from a privileged user on a guest operating system.

  - An error when Internet Explorer fails to validate User Mode Code Integrity (UMCI)
    policies.

  - An error in Microsoft Edge that could allow an attacker to escape from the
    AppContainer sandbox in the browser.

  - An error when Microsoft Edge improperly handles objects in memory.

  - An error when the win32k component improperly provides kernel information.

  - An error when Microsoft Windows PDF Library improperly handles objects in
    memory.

  - An error in the Microsoft JET Database Engine that could allow remote code
    execution on an affected system.

  - An error in Windows when the Win32k component fails to properly handle objects
    in memory.

  - An error in Windows Input Method Editor (IME) when IME improperly handles
    parameters in a method of a DCOM class.

  - An error when Microsoft Windows improperly handles NetBIOS packets.

  - This security update resolves a vulnerability in Windows Error Reporting
    (WER).");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to gain the same user rights as the current user, take control
  of the affected system, cause the host server to crash, run unsigned
  malicious code as though it were signed by a trusted source, run processes
  in an elevated context, install programs. View, change, or delete data
  or create new accounts with full user rights and gain access to sensitive
  information.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1607 x32/x64

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4034658");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100038");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98100");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100039");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99395");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99430");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100032");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100034");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100042");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100061");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100063");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100069");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100055");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100056");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100057");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100044");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100052");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100053");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100059");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100027");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100035");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100037");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100085");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100089");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100072");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100068");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100070");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100071");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.1592"))
{
  report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: 11.0.14393.0 - 11.0.14393.1592\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
