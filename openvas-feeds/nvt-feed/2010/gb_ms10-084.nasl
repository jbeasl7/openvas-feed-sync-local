# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902322");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-3222");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Windows Local Procedure Call Privilege Elevation Vulnerability (2360937)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2360937");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43777");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2631");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-084");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  with NetworkService privileges.");
  script_tag(name:"affected", value:"- Microsoft Windows 2003 Service Pack 2

  - Microsoft Windows XP Service Pack 3 and prior");
  script_tag(name:"insight", value:"The flaw is due to a stack overflow error in the Remote Procedure Call
  Subsystem (RPCSS) when exchanging port messages between LPC and the LRPC
  Server (RPC EndPoint Mapper).");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-084.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"2360937") == 0){
  exit(0);
}
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\Rpcrt4.dll");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

if(version_is_less(version:sysVer, test_version:"5.2.3790.4759")){
  report = report_fixed_ver(installed_version:sysVer, fixed_version:"5.2.3790.4759");
  security_message(port: 0, data: report);
}
