# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902663");
  script_version("2025-03-18T05:38:50+0000");
  script_cve_id("CVE-2012-0002", "CVE-2012-0152");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-03-14 09:43:49 +0530 (Wed, 14 Mar 2012)");
  script_name("Microsoft Remote Desktop Protocol Remote Code Execution Vulnerabilities (2671387) - Local Version Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2671387");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52353");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52354");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026790");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-020");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-020.");

  script_tag(name:"insight", value:"The flaws are due to the way Remote Desktop Protocol accesses an
  object in memory that has been improperly initialized or has been deleted and the way RDP service
  processes the packets.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary code as the logged-on user or cause a denial of service condition.");

  script_tag(name:"affected", value:"- Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:2, win2008:3) <= 0)
  exit(0);

sysPath = smb_get_systemroot();
if(!sysPath)
  exit(0);

rdpVer1 = fetch_file_version(sysPath:sysPath, file_name:"system32\drivers\Rdpwd.sys");
rdpVer2 = fetch_file_version(sysPath:sysPath, file_name:"system32\Rdpwsx.dll");
if(!rdpVer1 && !rdpVer2)
  exit(0);

if(rdpVer1) {
  if(hotfix_check_sp(xp:4) > 0) {
    if(version_is_less(version:rdpVer1, test_version:"5.1.2600.6187")) {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(win2003:3) > 0) {
    if(version_is_less(version:rdpVer1, test_version:"5.2.3790.4952")) {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if(hotfix_check_sp(winVista:3, win2008:3) > 0) {
    if(version_is_less(version:rdpVer1, test_version:"6.0.6002.18568") ||
       version_in_range(version:rdpVer1, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22773")) {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}

if(hotfix_check_sp(win7:2) > 0) {
  if(rdpVer1) {
    if(version_is_less(version:rdpVer1, test_version:"6.1.7600.16963") ||
       version_in_range(version:rdpVer1, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21150") ||
       version_in_range(version:rdpVer1, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17778") ||
       version_in_range(version:rdpVer1, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21923")) {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }

  if(rdpVer2) {
    if(version_is_less(version:rdpVer2, test_version:"6.1.7600.17009") ||
       version_in_range(version:rdpVer2, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21199") ||
       version_in_range(version:rdpVer2, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17827") ||
       version_in_range(version:rdpVer2, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21979")) {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
