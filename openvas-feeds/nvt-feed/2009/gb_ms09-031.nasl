# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900589");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-07-15 20:20:16 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1135");
  script_name("Microsoft ISA Server Privilege Escalation Vulnerability (970953)");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-031");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35631");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Exploitation could allow remote attackers to bypass security restrictions
  and to execute arbitrary code with the privileges of the user.");

  script_tag(name:"affected", value:"- Microsoft Internet Security and Acceleration (ISA) 2006 and with SP1

  - Microsoft Internet Security and Acceleration (ISA) 2006 with Update");

  script_tag(name:"insight", value:"When ISA Server 2006 authentication is configured with Radius OTP
  (One Time Password), an unspecified error occurs when authenticating
  requests using the HTTP-Basic method");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-031.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3) <= 0){
  exit(0);
}

if((hotfix_missing(name:"970811") == 0) ||
   (hotfix_missing(name:"971143") == 0)){
   exit(0);
}

exeFile = registry_get_sz(key:"SOFTWARE\Microsoft\Fpc", item:"InstallDirectory");
if(!exeFile){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exeFile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exeFile + "wspsrv.exe");

fileVer = GetVer(file:file, share:share);
if(!fileVer){
  exit(0);
}

# Microsoft ISA Server 2006
if(registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{DD4CEE59-5192-4CE1-8AFA-1CFA8EB37209}"))
{
  if(version_in_range(version:fileVer, test_version:"5.0.5720", test_version2:"5.0.5720.173")){
    security_message( port: 0, data: "The target host was found to be vulnerable" ); # ISA Server 2006
  }
  else if(version_in_range(version:fileVer, test_version:"5.0.5721", test_version2:"5.0.5721.262")){
    security_message( port: 0, data: "The target host was found to be vulnerable" ); # ISA Server 2006 with the Supportability Update installed
  }
  else if(version_in_range(version:fileVer, test_version:"5.0.5723", test_version2:"5.0.5723.513")){
    security_message( port: 0, data: "The target host was found to be vulnerable" ); # ISA Server 2006 with Service Pack 1
  }
  exit(0);
}
