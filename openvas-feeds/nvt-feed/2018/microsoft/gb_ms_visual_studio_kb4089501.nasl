# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813150");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2018-1037");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-04-19 12:58:52 +0530 (Thu, 19 Apr 2018)");
  script_name("Microsoft Visual Studio 2012 Update 5 Information Disclosure Vulnerability (KB4089501)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4089501.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Visual Studio improperly
  discloses limited contents of uninitialized memory while compiling program
  database (PDB) files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Microsoft Visual Studio 2012 Update 5.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-gb/help/4089501");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103715");

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
if(!vsVer || vsVer !~ "^11\."){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\VisualStudio\11.0");
}

else if("x64" >< os_arch){
 key_list = make_list("SOFTWARE\Microsoft\VisualStudio\11.0", "SOFTWARE\Wow6432Node\Microsoft\VisualStudio\11.0");
}

foreach key (key_list)
{
  installPath = registry_get_sz(key:key, item:"InstallDir");
  if(!installPath){
    continue;
  }

  dllVer = fetch_file_version(sysPath:installPath, file_name:"mspdbsrv.exe");
  if(dllVer && dllVer =~ "^11\.0" && version_is_less(version:dllVer, test_version:"11.0.61232.400"))
  {
    report = report_fixed_ver(file_checked: installPath + "mspdbsrv.exe",
                              file_version:dllVer, vulnerable_range:"11.0 - 11.0.61232.399");
    security_message(data:report);
    exit(0);
  }
}
exit(0);
