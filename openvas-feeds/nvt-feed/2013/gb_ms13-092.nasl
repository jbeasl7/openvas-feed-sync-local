# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901226");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-3898");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-11-15 12:40:59 +0530 (Fri, 15 Nov 2013)");
  script_name("Microsoft Hyper-V Privilege Elevation Vulnerability (2893986)");


  script_tag(name:"summary", value:"This host is missing an important security update according to
Microsoft Bulletin MS13-092.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"insight", value:"The issue is triggered when handling the value of a data structure, allowing
a memory address with an invalid address to be used.");
  script_tag(name:"affected", value:"- Microsoft Windows Server 2012

  - Microsoft Windows 8 x64 Edition");
  script_tag(name:"impact", value:"Successful exploitation allows guest OS users to execute arbitrary code in
all guest OS instances, and allows guest OS users to cause a denial of service
(host OS crash) via a guest-to-host hypercall with a crafted function parameter.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2893986");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63562");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-092");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Need to add Microsoft Windows 8 x64 Edition once we have the imag i.e win8x64:1
if(hotfix_check_sp(win2012:1) <= 0){
  exit(0);
}

## COnfirm Hyper-V is installed by checking vmms.exe
if(!registry_key_exists(key:"SOFTWARE\Classes\AppID\vmms.exe")){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Hvax64.exe");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.2.9200.16729")){
    report = report_fixed_ver(installed_version:sysVer, fixed_version:"6.2.9200.16729", install_path:sysPath);
    security_message(port: 0, data: report);
  }
  exit(0);
}
