# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902940");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-0005");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-01-09 12:59:12 +0530 (Wed, 09 Jan 2013)");
  script_name("Microsoft .NET Framework Open Data Protocol DOS Vulnerability (2769327)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2736416");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57141");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2736428");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2736418");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2736422");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-007");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute arbitrary code
  and cause a DoS (Denial of Service).");

  script_tag(name:"affected", value:"Microsoft .NET Framework 3.5, 3.5.1 and 4.");

  script_tag(name:"insight", value:"The flaw is due to an error within the WCF 'Replace()' function when handling
  Open Data Protocol (OData) data and can be exploited to exhaust system resources.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-004.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
                   win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(registry_key_exists(key:key))
{
  foreach item (registry_enum_keys(key:key))
  {
    path = registry_get_sz(key:key + item, item:"Path");
    if(path && "\Microsoft.NET\Framework" >< path)
    {
      dllVer = fetch_file_version(sysPath:path, file_name:"System.Data.Services.dll");
      if(dllVer)
      {
        # .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, Windows 7 and Windows Server 2008 R2
        if(version_in_range(version:dllVer, test_version:"4.0.30319.100", test_version2:"4.0.30319.296")||
           version_in_range(version:dllVer, test_version:"4.0.30319.500", test_version2:"4.0.30319.586"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}

key = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.5";
if(registry_key_exists(key:key))
{
  path = registry_get_sz(key:key, item:"All Assemblies In");
  if(path){
    dllv3 = fetch_file_version(sysPath:path, file_name:"System.Data.Services.dll");
  }
}

if(!dllv3){
  exit(0);
}

# .NET Framework 3.5 Service Pack 1 on Windows XP, Windows Server 2003, Windows Vista, and Windows Server 2008
if((hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win2008:3) > 0) &&
   (version_in_range(version:dllv3, test_version:"3.5.30729.4000", test_version2:"3.5.30729.4038")||
    version_in_range(version:dllv3, test_version:"3.5.30729.5000", test_version2:"3.5.30729.5850")))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

# .NET Framework 3.5.1 on Windows 7 and Windows Server 2008 R2
if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
   (version_in_range(version:dllv3, test_version:"3.5.30729.5000", test_version2:"3.5.30729.5005")||
    version_in_range(version:dllv3, test_version:"3.5.30729.5800", test_version2:"3.5.30729.5830")||
    version_in_range(version:dllv3, test_version:"3.5.30729.5400", test_version2:"3.5.30729.5450")))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
