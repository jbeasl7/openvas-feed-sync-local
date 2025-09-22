# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901301");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-2551");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-10-10 09:58:54 +0530 (Wed, 10 Oct 2012)");
  script_name("Microsoft Windows Kerberos Denial of Service Vulnerability (2743555)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2425227");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55778");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-069");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow authenticated attackers to cause a denial
  of service condition on the affected system.");
  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows 2008 R2 Service Pack 1 and prior");
  script_tag(name:"insight", value:"The flaw is present due to an error in Kerberos implementation which fails to
  properly handle a specially crafted session.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-069.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2008r2:2, win7:2, win7x64:2) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Kerberos.dll");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(win2008r2:2, win7:2, win7x64:2) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7600.17095") ||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21297") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.10000", test_version2:"6.1.7601.17925") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.20000", test_version2:"6.1.7601.22083")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
