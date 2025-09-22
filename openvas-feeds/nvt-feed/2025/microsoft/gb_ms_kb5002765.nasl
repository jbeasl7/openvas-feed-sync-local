# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836587");
  script_version("2025-08-15T15:42:26+0000");
  script_cve_id("CVE-2025-53761");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-12 18:15:45 +0000 (Tue, 12 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-13 16:42:08 +0530 (Wed, 13 Aug 2025)");
  script_name("Microsoft PowerPoint 2016 RCE Vulnerability (KB5002765)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002765");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution.");

  script_tag(name:"affected", value:"Microsoft PowerPoint 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002765");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

  if(exeVer =~ "^16\." && version_is_less(version:exeVer, test_version:"16.0.5513.1000")) {
    report = report_fixed_ver(file_checked:offPath + "\ppcore.dll", file_version:exeVer, vulnerable_range:"16.0 - 16.0.5513.999");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);