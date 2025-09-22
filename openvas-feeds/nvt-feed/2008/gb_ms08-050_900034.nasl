# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900034");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
  script_cve_id("CVE-2008-0082");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Windows Messenger Could Allow Information Disclosure Vulnerability (955702)");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30551");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-050.");

  script_tag(name:"insight", value:"Issue is in the Messenger.UIAutomation.1 ActiveX control being marked
  safe-for-scripting, which allows changing state, obtain contact information and a user's login ID.");

  script_tag(name:"affected", value:"- Microsoft Windows Messenger 4.7 on Microsoft Windows 2K/XP

  - Microsoft Windows Messenger 5.1 on Microsoft Windows 2K/XP/2003");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"impact", value:"Remote attackers can log on to a user's Messenger client as a user,
  and can initiate audio and video chat sessions without user interaction.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:3, win2k:5, win2003:3) <= 0){
  exit(0);
}

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Active Setup\Installed Components\{5945c046-1e7d-11d1-bc44-00c04fd912be}",
                          item:"KeyFileName");

dllPath = dllPath - "msmsgs.exe" + "msgsc.dll";

if(!registry_key_exists(key:"SOFTWARE\Clients\IM\Windows Messenger")){
  exit(0);
}

msngrVer = registry_get_sz(key:"SOFTWARE\Microsoft\Active Setup\Installed Components\{5945c046-1e7d-11d1-bc44-00c04fd912be}",
                           item:"Version");
if(!msngrVer){
  exit(0);
}

if("5.1" >< msngrVer){
  if(hotfix_missing(name:"899283") == 0)
    exit(0);

  vers = get_version(dllPath:dllPath, offs:60000);
  if(!vers)
    exit(0);

  if(version_is_less(version:vers, test_version:"5.1.0715")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"5.1.0715", file_checked:dllPath);
    security_message(port:0, data:report);
    exit(0);
  }
  exit(99);
}

else if("4.7" >< msngrVer){
  if(hotfix_check_sp(xp:4) > 0){
    if(hotfix_missing(name:"946648") == 0){
      exit(0);
    }
  }
  else if(hotfix_check_sp(win2003:3) > 0){
    if(hotfix_missing(name:"954723") == 0){
      exit(0);
    }
  }

  vers = get_version(dllPath:dllPath, offs:60000);
  if(!vers)
    exit(0);

  if(version_is_less(version:vers, test_version:"4.7.3002")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"4.7.3002", file_checked:dllPath);
    security_message(port:0, data:report);
    exit(0);
  }
  exit(99);
}
