# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901102");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-04-14 17:51:53 +0200 (Wed, 14 Apr 2010)");
  script_cve_id("CVE-2010-0478");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Media Services Remote Code Execution Vulnerability (980858)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0868");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-025");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code with
  system level privileges.");

  script_tag(name:"affected", value:"Microsoft Windows 2000 Server Service Pack 4 and prior.");

  script_tag(name:"insight", value:"This flaw is caused by a buffer overflow error in the Windows Media Unicast
  Service within the Windows Media Services component when handling transport
  information network packets, which could allow remote attackers to crash an
  affected service or execute arbitrary code by sending malformed packets.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-025.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5) <= 0){
 exit(0);
}

if(hotfix_missing(name:"980858") == 0){
  exit(0);
}


sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\windows media\server\Nsum.exe");

exeVer = GetVer(file:file, share:share);
if(!exeVer){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_is_less(version:exeVer, test_version:"4.1.0.3939")){
    report = report_fixed_ver(installed_version:exeVer, fixed_version:"4.1.0.3939");
    security_message(port: 0, data: report);
  }
}
