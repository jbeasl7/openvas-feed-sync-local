# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902230");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-08-11 15:08:29 +0200 (Wed, 11 Aug 2010)");
  script_cve_id("CVE-2010-1898", "CVE-2010-0019");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft .NET Common Language Runtime Remote Code Execution Vulnerability (2265906)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/983583/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42138");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42295");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2057");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-060");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to execute arbitrary
  code by tricking a user into visiting a specially crafted web page.");
  script_tag(name:"affected", value:"- Microsoft .NET Framework 3.5/SP 1

  - Microsoft .NET Framework 2.0 SP1/SP2");
  script_tag(name:"insight", value:"This flaw is caused by an error in the way the Common Language Runtime (CLR)
  handles delegates to virtual methods, which could be exploited to execute
  arbitrary code by tricking a user into visiting a malicious web page
  containing a specially crafted XBAP (XAML browser application).");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-060.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

# MS10-060 Hotfix check
if((hotfix_missing(name:"983583") == 0) || (hotfix_missing(name:"983589") == 0 ||
    hotfix_missing(name:"983590") == 0)){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    Ver = fetch_file_version(sysPath:path, file_name:"mscorlib.dll");
    if(Ver)
    {
      ## win xp, 2K3
      if(hotfix_check_sp(xp:4, win2k:5, win2003:3) > 0)
      {
        if(version_in_range(version:Ver, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3614") ||
           version_in_range(version:Ver, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4454"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:Ver, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4205")||
           version_in_range(version:Ver, test_version:"2.0.50727.4400", test_version2:"2.0.50727.4453"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      if(hotfix_check_sp(win7:1) > 0)
      {
        if(version_in_range(version:Ver, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4951")||
           version_in_range(version:Ver, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5017"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}
