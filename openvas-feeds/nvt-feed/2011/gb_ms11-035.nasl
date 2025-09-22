# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902516");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-05-11 14:45:15 +0200 (Wed, 11 May 2011)");
  script_cve_id("CVE-2011-1248");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows WINS Remote Code Execution Vulnerability (2524426)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2524426");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47730");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-167/");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-035");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code with elevated privileges or cause a denial-of-service condition.");
  script_tag(name:"affected", value:"- Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is caused by a logic error in the Windows Internet Name Service
  (WINS) when handling a socket send exception, which could cause certain user
  supplied values to remain within a stack frame and to be reused in another
  context, leading to arbitrary code execution with elevated privileges.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-035.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3, win2008:3) <= 0){
  exit(0);
}

## MS11-035 Hotfix (2524426)
if(hotfix_missing(name:"2524426") == 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

if(!registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\WINS")){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Wins.exe");
if(!exeVer){
  exit(0);
}

if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:exeVer, test_version:"5.2.3790.4849")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:exeVer, test_version:"6.0.6001.18629") ||
       version_in_range(version:exeVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22890")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:exeVer, test_version:"6.0.6002.18441") ||
       version_in_range(version:exeVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22620")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
