# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903310");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-06-12 12:56:11 +0530 (Wed, 12 Jun 2013)");
  script_name("Microsoft Update to Improve Cryptography and Digital Certificate Handling (2854544)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2813430");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2013/2854544");
  script_xref(name:"URL", value:"http://www.darkreading.com/attacks-breaches/flame-burns-microsoft-with-digital-certi/240001452");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_smb_windows_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to perform
  man-in-the-middle attack during a Windows Update session that basically
  redirects the user's machine to a phony update with the malware.");
  script_tag(name:"affected", value:"- Microsoft Windows 8

  - Microsoft Windows Server 2012

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is due to a Flame modules named 'Gadget' and 'Munch', used to infect
  other machines in the same network as the targeted machine.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Security Advisory (2854544).");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
   win8:1, win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Crypt32.dll");
if(!exeVer){
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.0.6002.18823") ||
     version_in_range(version:exeVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23094")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.1.7601.18142") ||
     version_in_range(version:exeVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22310")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_is_less(version:exeVer, test_version:"6.2.9200.16579")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
