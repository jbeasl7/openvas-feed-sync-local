# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811283");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-0174", "CVE-2017-0250", "CVE-2017-0293", "CVE-2017-8503",
                "CVE-2017-8591", "CVE-2017-8593", "CVE-2017-8620", "CVE-2017-8622",
                "CVE-2017-8623", "CVE-2017-8624", "CVE-2017-8627", "CVE-2017-8633",
                "CVE-2017-8634", "CVE-2017-8635", "CVE-2017-8636", "CVE-2017-8637",
                "CVE-2017-8638", "CVE-2017-8639", "CVE-2017-8640", "CVE-2017-8641",
                "CVE-2017-8642", "CVE-2017-8644", "CVE-2017-8645", "CVE-2017-8646",
                "CVE-2017-8647", "CVE-2017-8650", "CVE-2017-8652", "CVE-2017-8653",
                "CVE-2017-8655", "CVE-2017-8656", "CVE-2017-8657", "CVE-2017-8659",
                "CVE-2017-8661", "CVE-2017-8662", "CVE-2017-8664", "CVE-2017-8672",
                "CVE-2017-8673", "CVE-2017-8674", "CVE-2017-8666", "CVE-2017-8669",
                "CVE-2017-8670", "CVE-2017-8671");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-20 18:55:00 +0000 (Wed, 20 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-08-09 10:22:15 +0530 (Wed, 09 Aug 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4034674)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4034674");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error when Microsoft Edge improperly handles objects in memory.

  - An error when Microsoft browsers improperly access objects in memory.

  - An error when Microsoft Windows PDF Library improperly handles objects in
    memory.

  - An error when Windows Hyper-V on a host server fails to properly validate
    input from an authenticated user on a guest operating system.

  - An error when Windows Search handles objects in memory.

  - An error when Microsoft Hyper-V Network Switch on a host server fails to properly
    validate input from a privileged user on a guest operating system.

  - An error in the way that the Windows Subsystem for Linux handles NT pipes.

  - An error in the way Microsoft browsers handle objects in memory while rendering
    content.

  - An error when Windows Subsystem for Linux improperly handles objects in memory.

  - An error in Microsoft Edge that could allow an attacker to escape from
    the AppContainer sandbox in the browser.

  - An error when Microsoft Edge does not properly validate JavaScript under
    specific conditions..

  - An error in the way JavaScript engines render when handling objects in memory
    in Microsoft browsers.

  - An error when the win32k component improperly provides kernel information and
    fails to properly handle objects in memory..

  - An error in the way affected Microsoft scripting engines render when handling
    objects in memory.

  - An error in Remote Desktop Protocol (RDP) when an attacker connects to the target
    system using RDP and sends specially crafted requests.

  - An error in the Microsoft JET Database Engine that could allow remote code
    execution on an affected system.

  - An error in Edge how strings are validated in specific scenarios.

  - An error in Windows Input Method Editor (IME) when IME improperly handles
    parameters in a method of a DCOM class.

  - An error in Windows Error Reporting (WER).

  - An error in Microsoft Edge as a result of how memory is accessed in code compiled by
  the Edge Just-In-Time (JIT) compiler.

  - An error when Microsoft Windows improperly handles NetBIOS packets.

  - An error when the Chakra scripting engine does not properly handle objects in memory.

  - An error when Microsoft Edge does not properly enforce same-origin policies.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to sensitive information, gain the same user rights as the current
  user, execute arbitrary code on the host operating system, take control of the
  affected system, execute code with elevated permissions, run processes in an
  elevated context, cause a denial of service against the local system, cause the
  RDP service on the target system to stop responding, read sensitive data from
  memory and thereby potentially bypass Address Space Layout Randomization (ASLR),
  and bypass security feature.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1703 x32/x64.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4034674");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100038");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98100");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100039");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99395");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99430");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100032");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100034");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100040");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100042");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100061");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100065");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100069");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100043");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100055");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100056");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100049");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100057");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100046");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100044");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100052");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100053");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100054");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100048");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100059");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100027");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100035");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100037");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100031");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100085");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100072");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100079");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100081");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100089");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
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

if(version_in_range(version:edgeVer, test_version:"11.0.15063.0", test_version2:"11.0.15063.539"))
{
  report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: 11.0.15063.0 - 11.0.15063.539\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
