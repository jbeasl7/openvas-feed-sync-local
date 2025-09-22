# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834516");
  script_version("2024-10-11T05:05:54+0000");
  script_cve_id("CVE-2024-43483", "CVE-2024-43484");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-10-11 05:05:54 +0000 (Fri, 11 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-08 18:15:10 +0000 (Tue, 08 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-09 11:48:51 +0530 (Wed, 09 Oct 2024)");
  script_name("Microsoft .NET Framework Multiple DoS Vulnerabilities (KB5044021)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5044021");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-43483: .NET Framework Denial of service vulnerability

  - CVE-2024-43484: .NET Framework Denial of service vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct denial of service.");

  script_tag(name:"affected", value:"Microsoft .NET Framework 4.8 on Microsoft Windows 10 Version 1607 and Microsoft Windows Server 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5044021");

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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0) {
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ) {
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer) {
  exit(0);
}

if(edgeVer =~ "^11\.0\.14393"){
  if(!registry_key_exists(key:"SOFTWARE\Microsoft\.NETFramework")) {
    if(!registry_key_exists(key:"SOFTWARE\Microsoft\ASP.NET")) {
      if(!registry_key_exists(key:"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\")) {
        exit(0);
      }
    }
  }

  key_list = make_list("SOFTWARE\Microsoft\.NETFramework\", "SOFTWARE\Microsoft\ASP.NET\", "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\");

  foreach key(key_list) {
    if(".NETFramework" >< key) {
      foreach item (registry_enum_keys(key:key)) {
        NetPath = registry_get_sz(key:key + item, item:"InstallRoot");
        if(NetPath && "\Microsoft.NET\Framework" >< NetPath) {
          foreach item (registry_enum_keys(key:key)) {
            dotPath = NetPath + item;
            dllVer = fetch_file_version(sysPath:dotPath, file_name:"System.core.dll");

            if(dllVer) {
              if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4761")) {
                vulnerable_range = "4.8 - 4.8.4761" ;
                break;
              }
            }
          }
        }
      }
    }

    if((!vulnerable_range) && "ASP.NET" >< key) {
      foreach item (registry_enum_keys(key:key)) {
        dotPath = registry_get_sz(key:key + item, item:"Path");
        if(dotPath && "\Microsoft.NET\Framework" >< dotPath) {
          dllVer = fetch_file_version(sysPath:dotPath, file_name:"System.core.dll");
          if(dllVer) {
            if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4761")) {
              vulnerable_range = "4.8 - 4.8.4761" ;
              break;
            }
          }
        }
      }
    }

    ## For versions greater than 4.5 (https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#net_b)
    if((!vulnerable_range) && "NET Framework Setup" >< key) {
      dotPath = registry_get_sz(key:key, item:"InstallPath");

      if(dotPath && "\Microsoft.NET\Framework" >< dotPath) {
        dllVer = fetch_file_version(sysPath:dotPath, file_name:"System.core.dll");
        if(dllVer) {
          if(version_in_range(version:dllVer, test_version:"4.8", test_version2:"4.8.4761")){
            vulnerable_range = "4.8 - 4.8.4761" ;
          }
        }
      }
    }

    if(vulnerable_range) {
      report = report_fixed_ver(file_checked:dotPath + "System.core.dll",
                                file_version:dllVer, vulnerable_range:vulnerable_range);
      security_message(data:report);
      exit(0);
    }
  }
}
exit(99);
