# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832670");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2024-20673");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 18:15:47 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-14 11:02:37 +0530 (Wed, 14 Feb 2024)");
  script_name("Microsoft PowerPoint 2016 Remote Code Execution Vulnerability (KB5002495)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002495");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to,

  - Microsoft Office Remote Code Execution Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution on an affected system.");

  script_tag(name:"affected", value:"Microsoft PowerPoint 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002495");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/PowerPnt/Version", "MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

pptVer = get_kb_item("SMB/Office/PowerPnt/Version");
if(!pptVer) {
  exit(0);
}

if(!os_arch = get_kb_item("SMB/Windows/Arch")) {
  exit(0);
}

if("x86" >< os_arch) {
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
}
else if("x64" >< os_arch) {
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion");
}

foreach key(key_list) {
  commonpath = registry_get_sz(key:key, item:"ProgramFilesDir");
  if(!commonpath) {
    continue;
  }
  offPath = commonpath + "\Microsoft Office\OFFICE15" ;
  exeVer  = fetch_file_version(sysPath:offPath, file_name:"ppcore.dll");
  if(!exeVer) {
    exit(0);
  }

  if(exeVer =~ "^16\." && version_is_less(version:exeVer, test_version:"16.0.5435.1000")) {
    report = report_fixed_ver(file_checked:offPath + "\ppcore.dll", file_version:exeVer, vulnerable_range:"16.0 - 16.0.5435.0999");
    security_message(port:0, data:report);
  }
}

exit(99);
