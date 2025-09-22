# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901222");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-3868");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-09-11 12:41:50 +0530 (Wed, 11 Sep 2013)");
  script_name("Microsoft Windows Active Directory Denial of Service Vulnerability (2853587)");


  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
Bulletin MS13-079.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"insight", value:"Flaw is caused when the LDAP directory service fails to properly handle
a specially crafted LDAP query.");
  script_tag(name:"affected", value:"Active Directory Lightweight Directory Service (AD LDS) on,

  - Microsoft Windows 8

  - Microsoft Windows Server 2012

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to crash the service.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54750");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62184");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2853587");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-079");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3,
                   win2008r2:2, win8:1, win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

if(!(registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\NTDS"))){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Ntdsatq.dll");
if(!sysVer){
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.0.6002.18882") ||
     version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23154")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7601.18219") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22399")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8 and 2012
else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.2.9200.16664") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20771")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
