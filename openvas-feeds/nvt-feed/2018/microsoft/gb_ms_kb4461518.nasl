# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814278");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-8577");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-11-14 12:09:27 +0530 (Wed, 14 Nov 2018)");
  script_name("Microsoft Office Compatibility Pack Service Pack 3 Remote Code Execution Vulnerability (KB4461518)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4461518.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because Microsoft Excel fails to
  properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to run arbitrary code in the context
  of the current user.");

  script_tag(name:"affected", value:"Microsoft Office Compatibility Pack Service Pack 3.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4461518");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105834");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/ComptPack/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

cmpVer = get_kb_item("SMB/Office/ComptPack/Version");
if(!cmpVer || cmpVer !~ "^12\..*" ) exit( 0 );

os_arch = get_kb_item("SMB/Windows/Arch");
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
} else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion", "SOFTWARE\Microsoft\Windows\CurrentVersion");
}

foreach key(key_list){

  msPath = registry_get_sz(key:key, item:"ProgramFilesDir");
  if(msPath) {
    xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");

    if(xlcnvVer && xlcnvVer =~ "^12.*"){
      offpath = msPath + "\Microsoft Office\Office12";
      sysVer = fetch_file_version(sysPath:offpath, file_name:"excelcnv.exe");
      if(sysVer && version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6804.4999")) {
        report = report_fixed_ver(file_checked:offpath + "\excelcnv.exe",
                                  file_version:sysVer, vulnerable_range:"12.0 - 12.0.6804.4999");
        security_message(data:report);
        exit(0);
      }
    }
  }
}
