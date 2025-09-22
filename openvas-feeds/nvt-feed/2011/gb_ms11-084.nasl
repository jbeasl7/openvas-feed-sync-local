# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902485");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-2004");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-11-09 09:06:04 +0530 (Wed, 09 Nov 2011)");
  script_name("Windows Kernel-Mode Drivers Remote Code Execution Vulnerability (2617657)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2617657");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-084");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to gain elevated
  privileges or to run arbitrary code in kernel mode and take complete control
  of an affected system. An attacker could then install programs view, change,
  or delete data or create new accounts with full administrative rights.");

  script_tag(name:"affected", value:"Microsoft Windows 7 Service Pack 1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an array-indexing error in 'Win32k.sys' when
  parsing TrueType font files, which can be exploited by attackers to cause
  a denial of service.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host has moderate security update missing according to
  Microsoft Bulletin MS11-084.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2) <= 0){
  exit(0);
}

## MS11-084 Hotfix (2617657)
if(hotfix_missing(name:"2617657") == 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Win32k.sys");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(win7:2) > 0)
{
  if(version_in_range(version:sysVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16888")||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21059")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17696")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21827")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
