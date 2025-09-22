# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900095");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0077", "CVE-2009-0237");
  script_name("Microsoft ISA Server and Forefront Threat Management Gateway DoS Vulnerability (961759)");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-016");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34414");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34416");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Exploitation could allow remote user's to cause a web listener to stop
  responding to new requests and can also conduct cross site attacks.");

  script_tag(name:"affected", value:"- Microsoft Internet Security and Acceleration (ISA) 2004 (Ent and Std)

  - Microsoft Internet Security and Acceleration (ISA) 2006 and with SP1

  - Microsoft Internet Security and Acceleration (ISA) 2006 with Update");

  script_tag(name:"insight", value:"- Pop error in the firewall engine when handling the session state for
  Web proxy or Web publishing listeners.

  - An input validation error in the HTML forms authentication component
  (cookieauth.dll).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-016.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, win2003:3) <= 0){
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
  if(hotfix_missing(name:"968078") == 0){ # Hotfix for ISA 2006
    exit(0);
  }

  if(version_in_range(version:fileVer, test_version:"5.0.5720", test_version2:"5.0.5720.171")) {
    report = report_fixed_ver(installed_version:fileVer, vulnerable_range:"5.0.5720 - 5.0.5720.171");
    security_message(port: 0, data: report);
  }
  else if(version_in_range(version:fileVer, test_version:"5.0.5721", test_version2:"5.0.5721.260")) {
    report = report_fixed_ver(installed_version:fileVer, vulnerable_range:"5.0.5721 - 5.0.5721.260");
    security_message(port: 0, data: report);
  }
  else if(version_in_range(version:fileVer, test_version:"5.0.5723", test_version2:"5.0.5723.510")) {
    report = report_fixed_ver(installed_version:fileVer, vulnerable_range:"5.0.5723 - 5.0.5723.510");
    security_message(port: 0, data: report);
  }
  exit(0);
}

# Microsoft ISA Server 2004
else if(registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{0AC95D97-1B75-4AC7-B061-F21E379FF809}"))
{
  if(hotfix_missing(name:"960995") == 0){ # Hotfix for ISA 2004
    exit(0);
  }
  if(version_in_range(version:fileVer, test_version:"4.0.3445", test_version2:"4.0.3445.908")) {
    report = report_fixed_ver(installed_version:fileVer, vulnerable_range:"4.0.3445 - 4.0.3445.908");
    security_message(port: 0, data: report);
  }
  else if(version_in_range(version:fileVer, test_version:"4.0.2167", test_version2:"4.0.2167.908")) {
    report = report_fixed_ver(installed_version:fileVer, vulnerable_range:"4.0.2167 - 4.0.2167.908");
    security_message(port: 0, data: report);
  }
  exit(0);
}
