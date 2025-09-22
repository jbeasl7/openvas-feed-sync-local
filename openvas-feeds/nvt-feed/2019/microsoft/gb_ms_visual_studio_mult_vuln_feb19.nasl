# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814761");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2019-0613", "CVE-2019-0657");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-06 16:03:00 +0000 (Wed, 06 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-02-27 18:00:39 +0530 (Wed, 27 Feb 2019)");
  script_name("Microsoft Visual Studio Multiple Vulnerabilities (Feb 2019)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Update February-2019.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Visual Studio in the way they parse URL's.

  - An error in Visual Studio because it fails to check the source markup of a file.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code and bypass security logic conducting spoofing attacks.");

  script_tag(name:"affected", value:"Microsoft Visual Studio 2017 and 2017 Version 15.9.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0657");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0613");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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
if(!vsVer || vsVer !~ "^15\."){
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

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    vsname = registry_get_sz(key:key + item, item:"DisplayName");
    if(vsname =~ "^Visual Studio.*2017$")
    {
      install = registry_get_sz(key:key + item, item:"InstallLocation");
      if(install)
        vsversion = fetch_file_version(sysPath:install, file_name:"Common7\IDE\devenv.exe");
      if(!vsversion)
        continue;

      if(version_in_range(version:vsversion, test_version:"15.9", test_version2:"15.9.28307.344")){
        fix = "Visual Studio 2017 version 15.9.28307.423";
      }

      else if (version_in_range(version:vsversion, test_version:"15.0", test_version2:"15.0.26228.64")){
        fix = "Visual Studio 2017 version 15.0.26228.73";
      }
    }
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:vsversion, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}
exit(0);
