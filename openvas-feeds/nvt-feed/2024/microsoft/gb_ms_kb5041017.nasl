# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834309");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2024-38081");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 17:15:43 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-10 10:37:48 +0530 (Wed, 10 Jul 2024)");
  script_name("Microsoft .NET Framework Elevation of Privilege Vulnerability (KB5041017)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5041017");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an elevation of privilege
  vulnerability in the .NET Framework.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct privilege escalation.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 3.5, 4.7.2 and 4.8 on Microsoft Windows 10 version 1809 and Microsoft Windows Server 2019.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5041017");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2019:1) <= 0) {
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ) {
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer || edgeVer !~ "^11\.0\.17763") {
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\.NETFramework")){
  if(!registry_key_exists(key:"SOFTWARE\Microsoft\ASP.NET")){
    if(!registry_key_exists(key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\")){
      exit(0);
    }
  }
}

key_list = make_list("SOFTWARE\Microsoft\.NETFramework\", "SOFTWARE\Microsoft\ASP.NET\", "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\");

foreach key(key_list)
{
  if(".NETFramework" >< key)
  {
    foreach item (registry_enum_keys(key:key))
    {
      NetPath = registry_get_sz(key:key, item:"InstallRoot");
      if(NetPath && "\Microsoft.NET\Framework" >< NetPath)
      {
        foreach item (registry_enum_keys(key:key))
        {
          dotPath = NetPath + item;
          dllVer = fetch_file_version(sysPath:dotPath, file_name:"Mscorlib.dll");

          if(dllVer)
          {
            if(version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.9063"))
            {
              vulnerable_range = "2.0.50727.5700 - 2.0.50727.9063";
              break;
            }
            else if(version_in_range(version:dllVer, test_version:"4.7", test_version2:"4.7.4100"))
            {
              vulnerable_range = "4.7 - 4.7.4100" ;
              break;
            }

            else if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4738"))
            {
              vulnerable_range = "4.8 - 4.8.4738" ;
              break;
            }
          }
        }
        if(vulnerable_range){
          break;
        }
      }
    }

  }

  if((!vulnerable_range) && "ASP.NET" >< key)
  {
    foreach item (registry_enum_keys(key:key))
    {
      dotPath = registry_get_sz(key:key, item:"Path");
      if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
      {
        dllVer = fetch_file_version(sysPath:dotPath, file_name:"Mscorlib.dll");

        if(dllVer)
        {
          if(version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.9063"))
          {
            vulnerable_range = "2.0.50727.5700 - 2.0.50727.9063";
            break;
          }
          else if(version_in_range(version:dllVer, test_version:"4.7", test_version2:"4.7.4100"))
          {
            vulnerable_range = "4.7 - 4.7.4100" ;
            break;
          }

          else if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4738"))
          {
            vulnerable_range = "4.8 - 4.8.4738" ;
            break;
          }
        }
      }
    }
  }

  ## For versions greater than 4.5 (https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#net_b)
  if((!vulnerable_range) && "NET Framework Setup" >< key)
  {
    dotPath = registry_get_sz(key:key, item:"InstallPath");
    if(dotPath && "\Microsoft.NET\Framework" >< dotPath)
    {
      dllVer = fetch_file_version(sysPath:dotPath, file_name:"Mscorlib.dll");

      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.9063"))
        {
          vulnerable_range = "2.0.50727.5700 - 2.0.50727.9063";
          break;
        }
        else if(version_in_range(version:dllVer, test_version:"4.7", test_version2:"4.7.4100"))
        {
          vulnerable_range = "4.7 - 4.7.4100" ;
          break;
        }

        else if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4738"))
        {
          vulnerable_range = "4.8 - 4.8.4738" ;
          break;
        }
      }
    }
  }

  if(vulnerable_range)
  {
    report = report_fixed_ver(file_checked:dotPath + "\Mscorlib.dll",
                              file_version:dllVer, vulnerable_range:vulnerable_range);
    security_message(port:0, data:report);
    exit(0);
  }
}
exit(99);
