# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810577");
  script_version("2024-07-17T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-0037");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:52:00 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-03-01 14:28:21 +0530 (Wed, 01 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Edge and Internet Explorer Type Confusion RCE Vulnerability");

  script_tag(name:"summary", value:"Microsoft Edge or Internet Explorer is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a type confusion
  issue in the 'Layout::MultiColumnBoxBuilder::HandleColumnBreakOnColumnSpanningElement'
  function in mshtml.dll.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the currently logged-in user. Failed
  attacks will cause denial of service conditions.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2012R2

  - Microsoft Windows 10 Version 1511, 1607 x32/x64

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=1011");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96088");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41454");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1037906");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-007");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-006");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win2012R2:1, win8_1:1,
                   win8_1x64:1, win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}

iedllVer = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");

if(!edgeVer && !iedllVer){
  exit(0);
}

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1, win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less_equal(version:iedllVer, test_version:"11.0.9600.18538"))
  {
     Vulnerable_range1 = "11.0.9600.18538 and prior";
     VULN1 = TRUE ;
  }
}

else if((hotfix_check_sp(win2016:1) > 0))
{
  if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.693"))
  {
    Vulnerable_range2 = "11.0.14393.0 - 11.0.14393.693";
    VULN2 = TRUE ;
  }
}

else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less_equal(version:edgeVer, test_version:"11.0.10240.17236"))
  {
    Vulnerable_range2 = "11.0.10240.17236 and prior";
    VULN2 = TRUE;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.753"))
  {
    Vulnerable_range2 = "11.0.10586.0 - 11.0.10586.753";
    VULN2 = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.693"))
  {
    Vulnerable_range2 = "11.0.14393.0 - 11.0.14393.693";
    VULN2 = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\mshtml.dll" + '\n' +
           'File version:     ' +  iedllVer + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
