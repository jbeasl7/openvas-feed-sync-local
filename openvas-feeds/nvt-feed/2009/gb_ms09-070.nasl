# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901064");
  script_version("2025-03-05T05:38:52+0000");
  script_cve_id("CVE-2009-2508", "CVE-2009-2509");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-12-09 16:08:24 +0100 (Wed, 09 Dec 2009)");
  script_name("Microsoft Windows ADFS Remote Code Execution Vulnerability (971726)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/971726");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3434");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-070");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to take complete
  control of the victim's system.");
  script_tag(name:"affected", value:"- Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The vulnerability is due to incorrect validation of request headers when an
  authenticated user connects to an ADFS enabled Web Server. An attacker who
  successfully exploited this vulnerability could take complete control of an
  affected system.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-070.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-070");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3, win2008:3) <= 0){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\ADFS\Setup\Parameters")){
  exit(0);
}

# MS09-070 Hotfix check
if(hotfix_missing(name:"971726") == 0){
  exit(0);
}

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!dllPath){
  exit(0);
}

dllPath = dllPath - "\system32" + "\adfs\Adfsreg.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"5.2.3790.4578")){
      report = report_fixed_ver(installed_version:dllVer, fixed_version:"5.2.3790.4578", install_path:dllPath);
      security_message(port: 0, data: report);
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!dllPath){
  exit(0);
}

dllPath = dllPath + "\adfs\bin\Adfsgc.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18000")){
       report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6001.18000", install_path:dllPath);
       security_message(port: 0, data: report);
       exit(0);
    }
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18005")){
       report = report_fixed_ver(installed_version:dllVer, fixed_version:"6.0.6002.18005", install_path:dllPath);
       security_message(port: 0, data: report);
        exit(0);
    }
  }
}
