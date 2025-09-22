# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805164");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2015-1638");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-04-15 12:47:54 +0530 (Wed, 15 Apr 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Active Directory Federation Services Information Disclosure Vulnerability (3045711)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-040.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to the Active Directory
  Federation Services (AD FS) fails to properly log off a user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to users sensitive information.");

  script_tag(name:"affected", value:"Active Directory Federation Services
  3.0 on Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3045711");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-040");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2012R2:1) <= 0){
  exit(0);
}

adfs = registry_key_exists(key:"SOFTWARE\Microsoft\ADFS");
if(!adfs){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

adfs_ver = fetch_file_version(sysPath:sysPath, file_name:"\ADFS\Microsoft.identityserver.dll");
if(adfs_ver)
{
  if(version_is_less(version:adfs_ver, test_version:"6.3.9600.17720"))
  {
    report = report_fixed_ver(installed_version:adfs_ver, fixed_version:"6.3.9600.17720", install_path:sysPath);
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
