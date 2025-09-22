# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814638");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2018-8599");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-14 12:59:00 +0000 (Mon, 14 Sep 2020)");
  script_tag(name:"creation_date", value:"2018-12-28 14:00:04 +0530 (Fri, 28 Dec 2018)");
  script_name("Microsoft Visual Studio 'Diagnostic Hub Standard Collector' Elevation of Privilege Vulnerability");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Update December-2018.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when the Diagnostics Hub
  Standard Collector Service improperly impersonates certain file operations.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker who successfully exploited this vulnerability to gain elevated
  privileges.");

  script_tag(name:"affected", value:"- Microsoft Visual Studio 2017

  - Microsoft Visual Studio 2015 Update 3

  - Microsoft Visual Studio 2017 Version 15.9");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8599");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4469516");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes-v15.0");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_visual_prdts_detect.nasl");
  script_mandatory_keys("Microsoft/VisualStudio/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

vsVer = get_kb_item("Microsoft/VisualStudio/Ver");
if(!vsVer){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(vsVer =~ "^14\.")
{
  foreach key (key_list)
  {
    foreach item (registry_enum_keys(key:key))
    {
      upName = registry_get_sz(key:key + item, item:"DisplayName");
      if(upName =~ "^Microsoft Visual Studio 2015 Update 3")
      {
        if(!registry_key_exists(key:"SOFTWARE\Microsoft\Updates\Microsoft Visual Studio 2015\Update for Microsoft Visual Studio 2015 (KB4469516)") &&
           !registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Updates\Microsoft Visual Studio 2015\Update for Microsoft Visual Studio 2015 (KB4469516)"))
        {
          report = report_fixed_ver(installed_version:"Visual Studio 2015 " + vsVer, fixed_version:"14.0.27529.0");
          security_message(data:report);
          exit(0);
        }
      }
    }
  }
}

else if(vsVer =~ "^15\.")
{
  if("x86" >< os_arch){
    key_list_new = make_list("SOFTWARE\Microsoft\VisualStudio\SxS\VS7\");
  }

  else if("x64" >< os_arch){
    key_list_new = make_list("SOFTWARE\Microsoft\VisualStudio\SxS\VS7\",
                             "SOFTWARE\Wow6432Node\Microsoft\VisualStudio\SxS\VS7\");
  }

  foreach key (key_list_new)
  {
    installPath = registry_get_sz(key:key, item:"15.0");
    if(!installPath){
      continue;
    }

    binPath = installPath + "Common7\IDE\PrivateAssemblies\";
    dllVer = fetch_file_version(sysPath:binPath, file_name:"Microsoft.VisualStudio.Setup.dll");
  }

  if(dllVer)
  {
    if(version_is_less_equal(version:dllVer, test_version:"1.8.58.40810")){
      vulnerable_range = "Less than or equal to 1.8.58.40810";
    }
    else
    {
      foreach key (key_list)
      {
        foreach item (registry_enum_keys(key:key))
        {
          version = registry_get_sz(key:key + item, item:"DisplayVersion");
          if(version == "15.9.28307.53")
          {
            if(version_is_less(version:dllVer, test_version:"1.18.1042.9589")){
              vulnerable_range = "Less than 1.18.1042.9589";
            }
          }
        }
      }
    }
  }
}

if(vulnerable_range)
{
  report = report_fixed_ver(file_checked: binPath + "Microsoft.VisualStudio.Setup.dll",
                            file_version:dllVer, vulnerable_range:vulnerable_range);
  security_message(data:report);
  exit(0);
}
exit(0);
