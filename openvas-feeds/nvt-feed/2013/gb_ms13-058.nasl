# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902979");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2013-3154");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2013-07-10 10:05:39 +0530 (Wed, 10 Jul 2013)");
  script_name("Microsoft Windows Defender Privilege Elevation Vulnerability (2847927)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code in the security context of the LocalSystem account.");

  script_tag(name:"affected", value:"- Microsoft Windows Defender for

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error within Windows Defender
  related to pathnames and can be exploited to execute arbitrary code with system privileges.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-058.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54063/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60981");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2847927");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-058");

  script_dependencies("smb_reg_service_pack.nasl",
  "gb_ms_security_essentials_smb_login_detect.nasl");

  script_mandatory_keys("SMB/WindowsVersion", "microsoft/defender/mpclient");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2)<=0){
  exit(0);
}

defender_ver = get_kb_item("microsoft/defender/mpclient");
if(!defender_ver)
  exit(0);

if(version_is_less(version:defender_ver, test_version:"6.1.7600.17316") ||
   version_in_range(version:defender_ver, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21530")||
   version_in_range(version:defender_ver, test_version:"6.1.7601.17000", test_version2:"6.1.7601.18169")||
   version_in_range(version:defender_ver, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22340"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}