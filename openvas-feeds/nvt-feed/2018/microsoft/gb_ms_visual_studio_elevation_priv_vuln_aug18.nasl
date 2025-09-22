# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813781");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2018-0952");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-08-16 16:40:35 +0530 (Thu, 16 Aug 2018)");
  script_name("Microsoft Visual Studio 'Diagnostic Hub Standard Collector' Elevation Of Privilege Vulnerability (Aug 2018)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error when the
  'Diagnostics Hub Standard Collector' or 'Visual Studio Standard Collector'
  allows file creation in arbitrary locations.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to run a specially crafted application and take control of an
  affected system.");

  script_tag(name:"affected", value:"- Microsoft Visual Studio 2017

  - Microsoft Visual Studio 2015 Update 3

  - Microsoft Visual Studio 2017 Version 15.8");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0952");
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

## VS 2015
## Microsoft Visual Studio 2015 Update 3 : Covered in KB4469516

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\VisualStudio\SxS\VS7");
}

else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\VisualStudio\SxS\VS7", "SOFTWARE\Wow6432Node\Microsoft\VisualStudio\SxS\VS7");
}

foreach key (key_list)
{
  installPath = registry_get_sz(key:key, item:"15.0");
  if(!installPath){
    continue;
  }

  binPath = installPath + "Common7\IDE\PrivateAssemblies\";
  dllVer = fetch_file_version(sysPath:binPath, file_name:"Microsoft.VisualStudio.Setup.dll");
  if(dllVer)
  {
    ##For VS 2017 15.0
    if(version_is_less(version:dllVer, test_version:"1.8.58.40810")){
      vulnerable_range = "Less than 1.8.58.40810";
    }

    ##For VS 2017 15.8
    else if(version_in_range(version:dllVer, test_version:"1.15.0", test_version2:"1.17.1222.28280")){
      vulnerable_range = "1.15 - 1.17.1222.28280";
    }

    if(vulnerable_range)
    {
      report = report_fixed_ver(file_checked: binPath + "Microsoft.VisualStudio.Setup.dll",
                                file_version:dllVer, vulnerable_range:vulnerable_range);
      security_message(data:report);
      exit(0);
    }
  }
}
exit(0);
