# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902828");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-0163");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-04-11 09:21:20 +0530 (Wed, 11 Apr 2012)");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerability (2671605)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2671605");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52921");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026904");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-025");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary code
  with the privileges of the currently logged-in user. Failed attacks will
  cause denial-of-service conditions.");

  script_tag(name:"affected", value:"- Microsoft .NET Framework 4.0

  - Microsoft .NET Framework 3.5.1

  - Microsoft .NET Framework 2.0 Service Pack 2

  - Microsoft .NET Framework 1.1 Service Pack 1");

  script_tag(name:"insight", value:"The flaw is due to an error within the .NET CRL (Common Language
  Runtime) when handling certain parameters passed to a function and can be
  exploited via a specially crafted web page.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-025.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if(path && "\Microsoft.NET\Framework" >< path)
  {
    dllVer = fetch_file_version(sysPath:path, file_name:"System.Drawing.dll");
    if(dllVer)
    {
      ## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, Windows 7
      if(version_in_range(version:dllVer, test_version:"4.0.30319.000", test_version2:"4.0.30319.281")||
         version_in_range(version:dllVer, test_version:"4.0.30319.500", test_version2:"4.0.30319.567"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 3.5.1 on Windows 7
      if((hotfix_check_sp(win7:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4979")||
          version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5461")||
          version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.5728")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4229")||
          version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.5728")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows XP and Windows Server 2003
      if((hotfix_check_sp(xp:4, win2003:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3638")||
          version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.5728")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }

      ## .NET Framework 1.1 Service Pack 1 on Windows XP, Windows Server 2003, Windows Vista and Windows Server 2008
      if((hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2496")))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
