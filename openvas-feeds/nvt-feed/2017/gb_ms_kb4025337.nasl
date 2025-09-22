# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811519");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-0170", "CVE-2017-8463", "CVE-2017-8467", "CVE-2017-8486",
                "CVE-2017-8495", "CVE-2017-8556", "CVE-2017-8557", "CVE-2017-8563",
                "CVE-2017-8564", "CVE-2017-8565", "CVE-2017-8573", "CVE-2017-8577",
                "CVE-2017-8578", "CVE-2017-8580", "CVE-2017-8581", "CVE-2017-8582",
                "CVE-2017-8587", "CVE-2017-8588", "CVE-2017-8589", "CVE-2017-8590",
                "CVE-2017-8592");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-12 10:12:05 +0530 (Wed, 12 Jul 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4025337)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4025337");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist:

  - When Microsoft Browsers improperly handle redirect requests.

  - In Microsoft Windows when Win32k fails to properly handle objects in memory.

  - In Windows when the Microsoft Graphics Component fails to properly handle
    objects in memory.

  - In Microsoft Windows when Kerberos falls back to NT LAN Manager (NTLM)
    Authentication Protocol as the default authentication protocol.

  - When Windows Explorer improperly handles executable files and shares during
    rename operations.

  - When Windows improperly handles objects in memory.

  - In the Windows System Information Console when it improperly parses
    XML input containing a reference to an external entity.

  - In Microsoft Windows when Kerberos fails to prevent tampering with the SNAME
    field during ticket exchange.

  - In the way that Microsoft WordPad parses specially crafted files.

  - When Windows Search handles objects in memory.

  - When the Windows kernel fails to properly initialize a memory address,
    allowing an attacker to retrieve information that could lead to a Kernel
    Address Space Layout Randomization (KASLR) bypass.

  - In PowerShell when PSObject wraps a CIM Instance.

  - When Windows Explorer attempts to open a non-existent file.

  - In the Windows Performance Monitor Console when it improperly parses XML
    input containing a reference to an external entity.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to force the browser to send data that would otherwise be restricted to a
  destination web site of their choice, to obtain information to further
  compromise the user's system, to run arbitrary code in kernel mode, to run
  processes in an elevated context, to run arbitrary code in the context of
  another user, to could read arbitrary files via an XML external entity (XXE)
  declaration, to bypass Extended Protection for Authentication, take control
  of the affected system, retrieve the base address of the kernel driver from
  a compromised process, execute malicious code on a vulnerable system, cause
  a denial of service, obtain information to further compromise the system.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025337");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99389");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99409");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99414");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99424");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99439");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99398");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99402");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99428");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99394");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99431");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99416");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99419");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99421");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99423");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99429");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99413");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99425");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99427");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99396");
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

fileVer = fetch_file_version(sysPath:sysPath, file_name:"win32k.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.23848"))
{
  report = 'File checked:     ' + sysPath + "\win32k.sys" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range:  Less than 6.1.7601.23848\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
