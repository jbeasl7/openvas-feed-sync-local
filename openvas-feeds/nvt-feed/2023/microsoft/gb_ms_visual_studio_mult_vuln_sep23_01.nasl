# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832280");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2023-36758", "CVE-2023-36759", "CVE-2023-36792", "CVE-2023-36793",
                "CVE-2023-36794", "CVE-2023-36796", "CVE-2023-36799");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-15 14:14:00 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-14 11:44:15 +0530 (Thu, 14 Sep 2023)");
  script_name("Microsoft Visual Studio Multiple Vulnerabilities-01 (Sep 2023)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Update September-2023.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple remote
  code execution, elevation of privilege and denial of service vulnerabilities in
  Microsoft Visual Studio.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause denial of service, elevate privileges and execute arbitrary code
  on an affected system.");

  script_tag(name:"affected", value:"Microsoft Visual Studio 2022 version 17.7 prior to 17.7.4.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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
if(!vsVer || vsVer !~ "^17\."){
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
    if(vsname =~ "^Visual Studio.*2022$")
    {
      install = registry_get_sz(key:key + item, item:"InstallLocation");
      if(install)
        vsversion = fetch_file_version(sysPath:install, file_name:"Common7\IDE\devenv.exe");
      if(!vsversion)
        vsversion = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(!vsversion)
        continue;

      if (version_in_range(version:vsversion, test_version:"17.7", test_version2:"17.7.34031.278")) {
        report = report_fixed_ver(installed_version:vsversion, fixed_version:"Visual Studio 2022 version 17.7.4");
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
