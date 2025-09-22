# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834956");
  script_version("2025-02-14T08:35:38+0000");
  script_cve_id("CVE-2025-21390", "CVE-2025-21383");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-14 08:35:38 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-11 18:15:37 +0000 (Tue, 11 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-12 14:15:29 +0530 (Wed, 12 Feb 2025)");
  script_name("Microsoft Office 2016 Multiple Vulnerabilities (KB5002179)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002179");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2025-21390: Microsoft Office Remote Code Execution Vulnerability

  - CVE-2025-21383: Microsoft Office Information Disclosure Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct remote code execution and disclose information.");

  script_tag(name:"affected", value:"Microsoft Office 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002179");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer || officeVer !~ "^16\."){
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
      if(version_is_less(version:ortVer, test_version:"16.0.5487.1000"))
      {
        report = report_fixed_ver( file_checked:comPath + "Gkexcel.dll",
                                   file_version:ortVer, vulnerable_range:"16.0 - 16.0.5487.0999");
        security_message(data:report);
        exit(0);
      }
    }
  }
}
exit(0);