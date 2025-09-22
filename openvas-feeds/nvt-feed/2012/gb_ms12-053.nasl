# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902922");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-2526");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-08-15 10:45:43 +0530 (Wed, 15 Aug 2012)");
  script_name("Microsoft Remote Desktop Protocol Remote Code Execution Vulnerability (2723135)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2723135");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54935");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50244");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-053");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code as the logged-on user or cause a denial of service condition.");

  script_tag(name:"affected", value:"Microsoft Windows XP x32 Service Pack 3 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error within Remote Desktop Services when
  accessing an object in memory after it has been deleted. This can be
  exploited by sending a sequence of specially crafted RDP packets to the
  target system.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-053.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

dkey = registry_key_exists(key:"SYSTEM\CurrentControlSet\Control\Terminal Server");
if(!dkey){
  exit(0);
}

##  Exit if RDP is not enabled
dValue = registry_get_dword(key:dkey, item:"fDenyTSConnections");
if(dValue && (int(dValue) == 1)){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

rdpVer = fetch_file_version(sysPath:sysPath, file_name:"system32\drivers\Rdpwd.sys");
if(!rdpVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:rdpVer, test_version:"5.1.2600.6258")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
