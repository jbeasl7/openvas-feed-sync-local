# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836261");
  script_version("2025-09-11T05:38:37+0000");
  script_cve_id("CVE-2025-54901");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-09 17:16:01 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-10 06:59:47 +0000 (Wed, 10 Sep 2025)");
  script_name("Microsoft Excel 2016 Information Disclosure Vulnerability (KB5002762)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002762");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct information disclosure.");

  script_tag(name:"affected", value:"Microsoft Excel 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002762");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(!excelVer) {
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot");
}
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\InstallRoot",
                        "SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot");
}

foreach key (key_list)
{
  comPath = registry_get_sz(key:key, item:"Path");
  if(comPath)
  {
    ortVer = fetch_file_version(sysPath:comPath, file_name:"Gkexcel.dll");
    if(ortVer && ortVer =~ "^16\.")
    {
      if(version_is_less(version:ortVer, test_version:"16.0.5517.1000"))
      {
        report = report_fixed_ver( file_checked:comPath + "Gkexcel.dll",
                                   file_version:ortVer, vulnerable_range:"16.0 - 16.0.5517.999");
        security_message(port:0, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
