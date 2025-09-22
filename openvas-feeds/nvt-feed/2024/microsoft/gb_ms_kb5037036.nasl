# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832694");
  script_version("2024-04-12T15:39:03+0000");
  script_cve_id("CVE-2024-21409");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-04-12 15:39:03 +0000 (Fri, 12 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-09 17:15:34 +0000 (Tue, 09 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-10 15:32:36 +0530 (Wed, 10 Apr 2024)");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerability (KB5037036)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5037036");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a remote code execution
  vulnerability in the .NET Framework.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 3.5, 4.8 and 4.8.1 on Microsoft Windows 10, version 22H2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5037036");

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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0) {
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ) {
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)) {
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build || "19045" >!< build) {
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer || edgeVer !~ "^11\.0\.19041") {
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
          dllVer1 = fetch_file_version(sysPath:dotPath, file_name:"System.dll");
          dllVer2 = fetch_file_version(sysPath:dotPath, file_name:"System.printing.dll");

          if(dllVer1 || dllVer2)
          {
            if(dllVer2 && version_in_range(version:dllVer2, test_version:"3.0.6920.8600", test_version2:"3.0.6920.9160"))
            {
              VULN2 = TRUE ;
              vulnerable_range = "3.0.6920.8600 - 3.0.6920.9160";
              break;
            }
            else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.8", test_version2:"4.8.4717"))
            {
              VULN1 = TRUE ;
              vulnerable_range = "4.8 - 4.8.4717" ;
              break;
            }

            else if(version_in_range(version:dllVer1, test_version:"4.8.9000", test_version2:"4.8.9235"))
            {
              VULN1 = TRUE ;
              vulnerable_range = "4.8.9000 - 4.8.9235" ;
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
        dllVer1 = fetch_file_version(sysPath:dotPath, file_name:"System.dll");
        dllVer2 = fetch_file_version(sysPath:dotPath, file_name:"System.printing.dll");

        if(dllVer1 || dllVer2)
        {
          if(dllVer2 && version_in_range(version:dllVer2, test_version:"3.0.6920.8600", test_version2:"3.0.6920.9160"))
          {
            VULN2 = TRUE ;
            vulnerable_range = "3.0.6920.8600 - 3.0.6920.9160";
            break;
          }
          else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.8", test_version2:"4.8.4717"))
          {
            VULN1 = TRUE ;
            vulnerable_range = "4.8 - 4.8.4717" ;
            break;
          }

          else if(version_in_range(version:dllVer1, test_version:"4.8.9000", test_version2:"4.8.9235"))
          {
            VULN1 = TRUE ;
            vulnerable_range = "4.8.9000 - 4.8.9235" ;
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
      dllVer1 = fetch_file_version(sysPath:dotPath, file_name:"System.dll");
      dllVer2 = fetch_file_version(sysPath:dotPath, file_name:"System.printing.dll");

      if(dllVer1 || dllVer2)
      {
        if(dllVer2 && version_in_range(version:dllVer2, test_version:"3.0.6920.8600", test_version2:"3.0.6920.9160"))
        {
          VULN2 = TRUE ;
          vulnerable_range = "3.0.6920.8600 - 3.0.6920.9160";
          break;
        }
        else if(dllVer1 && version_in_range(version:dllVer1, test_version:"4.8", test_version2:"4.8.4717"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "4.8 - 4.8.4717" ;
          break;
        }

        else if(version_in_range(version:dllVer1, test_version:"4.8.9000", test_version2:"4.8.9235"))
        {
          VULN1 = TRUE ;
          vulnerable_range = "4.8.9000 - 4.8.9235" ;
          break;
        }
      }
    }
  }

  if(VULN1)
  {
    report = report_fixed_ver(file_checked:dotPath + "\System.dll",
                              file_version:dllVer1, vulnerable_range:vulnerable_range);
    security_message(port:0, data:report);
    exit(0);
  }

  if(VULN2)
  {
    report = report_fixed_ver(file_checked:dotPath + "\System.printing.dll",
                              file_version:dllVer2, vulnerable_range:vulnerable_range);
    security_message(port:0, data:report);
    exit(0);
  }
}
exit(99);
