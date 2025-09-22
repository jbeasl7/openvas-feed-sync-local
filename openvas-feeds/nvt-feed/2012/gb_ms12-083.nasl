# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901305");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-2549");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-12-12 09:40:29 +0530 (Wed, 12 Dec 2012)");
  script_name("Microsoft Windows IP-HTTPS Component Security Feature Bypass Vulnerability (2765809)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2765809");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56840");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-083");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_smb_windows_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow attacker to bypass certain security
  restrictions.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to error in the IP-HTTPS component, which fails to validate
  the certificates. This can lead to a revoked certificate being considered as
  valid.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-083.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2008r2:2) <= 0){
  exit(0);
}

iphlpsvcPath = smb_get_systemroot();
if(!iphlpsvcPath){
  exit(0);
}

iphlpsvcVer = fetch_file_version(sysPath:iphlpsvcPath, file_name:"system32\Iphlpsvc.dll");

## before 6.1.7600.17157 and 6.1.7600.22000 before 6.1.7600.21360 (RTM)
## before 6.1.7601.17989 and 6.1.7601.21000 before 6.1.7601.22150 (SP1)
if(iphlpsvcVer && (version_is_less(version:iphlpsvcVer, test_version:"6.1.7600.17157") ||
   version_in_range(version:iphlpsvcVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21359")||
   version_in_range(version:iphlpsvcVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17988")||
   version_in_range(version:iphlpsvcVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22149"))){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
