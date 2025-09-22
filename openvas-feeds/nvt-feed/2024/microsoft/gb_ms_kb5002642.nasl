# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834750");
  script_version("2024-11-15T15:55:05+0000");
  script_cve_id("CVE-2024-49032", "CVE-2024-49031");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-15 15:55:05 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-12 18:15:43 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-14 09:40:17 +0530 (Thu, 14 Nov 2024)");
  script_name("Microsoft Office 2016 Multiple Vulnerabilities (KB5002642)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002642");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-49032: Microsoft Office Graphics Remote Code Execution Vulnerability

  - CVE-2024-49031: Microsoft Office Graphics Remote Code Execution Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution.");

  script_tag(name:"affected", value:"Microsoft Office 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002642");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer){
  exit(0);
}

if(officeVer =~ "^16\.") {
  os_arch = get_kb_item("SMB/Windows/Arch");
  if("x86" >< os_arch) {
    key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
  }
  else if("x64" >< os_arch) {
    key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                          "SOFTWARE\Microsoft\Windows\CurrentVersion");
  }

  foreach key(key_list)
  {
    propath = registry_get_sz(key:key, item:"ProgramFilesDir");
    if(propath) {
      offPath = propath + "\Microsoft Office\root\Office16";
      offexeVer = fetch_file_version(sysPath:offPath, file_name:"firstrun.exe");
      if(!offexeVer) {
        continue ;
      }

      if(offexeVer =~ "^16\." && "x64" >< os_arch && version_is_less(version:offexeVer, test_version:"16.0.5149.1000")) {
        report = report_fixed_ver(file_checked:offPath + "\firstrun.exe",
                 file_version:offexeVer, vulnerable_range:"16.0 - 16.0.5149.0999");
        security_message(port:0, data:report);
        exit(0);
      }

      if(offexeVer =~ "^16\." && "x86" >< os_arch && version_is_less(version:offexeVer, test_version:"16.0.5413.1000")) {
        report = report_fixed_ver(file_checked:offPath + "\firstrun.exe",
                 file_version:offexeVer, vulnerable_range:"16.0 - 16.0.5413.0999");
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

exit(99);