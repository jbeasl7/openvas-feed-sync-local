# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834518");
  script_version("2024-10-11T05:05:54+0000");
  script_cve_id("CVE-2024-43483", "CVE-2024-43484");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-10-11 05:05:54 +0000 (Fri, 11 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-08 18:15:10 +0000 (Tue, 08 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-09 11:48:51 +0530 (Wed, 09 Oct 2024)");
  script_name("Microsoft .NET Framework Multiple DoS Vulnerabilities (KB5044033)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5044033");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-43483: .NET Framework Denial of service vulnerability

  - CVE-2024-43484: .NET Framework Denial of service vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct denial of service.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 3.5 and 4.8.1 on Microsoft Windows 11, version 22H2 and Microsoft Windows 11, version 23H2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5044033");

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

if(hotfix_check_sp(win11:1) <= 0) {
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)) {
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build || (build != "22621" && build != "22631")) {
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
            if(version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.9178"))
            {
              vulnerable_range = "2.0.50727.5700 - 2.0.50727.9178";
              break;
            }
            else if(version_in_range(version:dllVer, test_version:"4.8.9000", test_version2:"4.8.9276.0"))
            {
              vulnerable_range = "4.8.9000 - 4.8.9276" ;
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
          if(version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.9178"))
          {
            vulnerable_range = "2.0.50727.5700 - 2.0.50727.9178";
            break;
          }
          else if(version_in_range(version:dllVer, test_version:"4.8.9000", test_version2:"4.8.9276.0"))
          {
            vulnerable_range = "4.8.9000 - 4.8.9276" ;
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
        if(version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.9178"))
        {
          vulnerable_range = "2.0.50727.5700 - 2.0.50727.9178";
          break;
        }
        else if(version_in_range(version:dllVer, test_version:"4.8.9000", test_version2:"4.8.9276.0"))
        {
          vulnerable_range = "4.8.9000 - 4.8.9276" ;
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
