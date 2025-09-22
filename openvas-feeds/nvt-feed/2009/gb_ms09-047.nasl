# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901012");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-10 15:23:12 +0200 (Thu, 10 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2498", "CVE-2009-2499");
  script_name("Microsoft Windows Media Format Remote Code Execution Vulnerability (973812)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/968816");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36225");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36228");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2566");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-047");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code or
  compromise an affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows Media Service 9.1 on Microsoft Windows 2k3 SP2 and prior

  - Microsoft Windows Media Format 9.0 on Microsoft Windows 2k SP4/XP SP3/2k3 SP2 and prior

  - Microsoft Windows Media Format 9.5 on Microsoft Windows XP SP3/2k3 SP2 and prior

  - Microsoft Windows Media Format 11.0 on Microsoft Windows XP SP3 and prior

  - Microsoft Windows Media Format 11.0 on Microsoft Windows Vista SP2 and prior

  - Microsoft Windows Media Format 11.0 on Microsoft Windows 2008 Server SP2 and prior");

  script_tag(name:"insight", value:"- An error exists in the handling of ASF file headers and can be exploited
    to trigger an invalid call to freed memory via a specially crafted file
    or specially crafted streaming content from a web site.

  - An error in the processing of MP3 meta-data can be exploited to corrupt
    memory via a specially crafted MP3 file or specially crafted streaming
    content from a web site.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-047.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# MS09-047 Hotfix check
if((hotfix_missing(name:"968816") == 0)||(hotfix_missing(name:"972554") == 0))
{
  exit(0);
}

dllPath = registry_get_sz(item:"Install Path",
                          key:"SOFTWARE\Microsoft\COM3\Setup");
if(!dllPath)
{
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);

# Code for Windows Media Service
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\windows media\server\Wmsserver.dll");
dllVer = GetVer(file:file, share:share);

if(dllVer)
{
  if(hotfix_check_sp(win2003:3) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"9.1.1.5001"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
    }
  }
}

# Code for Windows Media Format
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\Wmvcore.dll");
dllVer = GetVer(file:file, share:share);

if(!dllVer)
{
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_is_less(version:dllVer, test_version:"9.0.0.3270")||
     version_in_range(version:dllVer, test_version:"9.0.0.3300", test_version2:"9.0.0.3361")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    #         10.0.0.4300 < 10.0.0.4372, 10.0.0.4000 < 10.0.0.4072 and 11.0 < 11.0.5721.5265
    if(version_is_less(version:dllVer, test_version:"9.0.0.3270")||
       version_in_range(version:dllVer, test_version:"9.0.0.3300",test_version2:"9.0.0.3361")||
       version_in_range(version:dllVer, test_version:"10.0",test_version2:"10.0.0.3704")||
       version_in_range(version:dllVer, test_version:"10.0.0.4300",test_version2:"10.0.0.4371")||
       version_in_range(version:dllVer, test_version:"10.0.0.4000",test_version2:"10.0.0.4071")||
       version_in_range(version:dllVer, test_version:"11.0",test_version2:"11.0.5721.5264")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  else if("Service Pack 3" >< SP)
  {
    #      10.0.0.4000 < 10.0.0.4072 and 11.0 < 11.0.5721.5265
    if(version_is_less(version:dllVer, test_version:"9.0.0.4506") ||
       version_in_range(version:dllVer, test_version:"10.0",test_version2:"10.0.0.3704") ||
       version_in_range(version:dllVer, test_version:"10.0.0.4300",test_version2:"10.0.0.4371") ||
       version_in_range(version:dllVer, test_version:"10.0.0.4000",test_version2:"10.0.0.4071") ||
       version_in_range(version:dllVer, test_version:"11.0",test_version2:"11.0.5721.5264")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  else
    security_message( port: 0, data: "The target host was found to be vulnerable" );
}
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"10.0.0.4005")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  else
    security_message( port: 0, data: "The target host was found to be vulnerable" );
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\System32\Wmvcore.dll");

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"11.0.6001.7006")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
      exit(0);
  }

  if("Service Pack 2" >< SP)
  {
      if(version_is_less(version:dllVer, test_version:"11.0.6002.18049")){
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
    if(version_is_less(version:dllVer, test_version:"11.0.6001.7006")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"11.0.6002.18049")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
