# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900035");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
  script_cve_id("CVE-2008-1456", "CVE-2008-1457");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Vulnerabilities in Event System Could Allow Remote Code Execution (950974)");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-049");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30584");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-049.");

  script_tag(name:"insight", value:"Issues are due to the Microsoft Windows Event System does not properly
  validate the range of indexes when calling an array of function pointers
  and fails to handle per-user subscription requests.");

  script_tag(name:"affected", value:"Microsoft Windows 2K/XP/2003.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"impact", value:"Remote exploitation allows attackers to execute arbitrary code
  with system privileges.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:3, win2k:5, win2003:3, winVista:2, win2008:2) <= 0){
  exit(0);
}

if(hotfix_missing(name:"950974") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}

dllPath = sysPath + "\Es.dll";

if(hotfix_check_sp(win2k:5) > 0) {
  vers = get_version(dllPath:dllPath, offs:150000);
  if(vers == NULL){
    exit(0);
  }

  if(ereg(pattern:"^(1999\..*|2000\.(1\..*|2\.([0-2]?[0-9].|3[0-4].*|" +
                  "35[0-4][0-9]\..*)))$", string:vers)){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

else if(hotfix_check_sp(xp:4) > 0) {
  vers = get_version(dllPath:dllPath, offs:150000);
  if(vers == NULL){
    exit(0);
  }

  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP) {
    if(ereg(pattern:"^(2000\..*|2001\.(0?[0-9]\..*|1[01]\..*|12\." +
                    "([0-3]?[0-9].*|4[0-3].*|440[0-9]\..*|441[0-3]" +
                    "\..*|4414\.([0-2]?[0-9]?[0-9]|3[01][0-9])))).?$",
            string:vers)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if("Service Pack 3" >< SP) {
    if(ereg(pattern:"^(2000\..*|2001\.(0?[0-9]\..*|1[01]\..*|12\." +
                    "([0-3]?[0-9].*|4[0-3].*|440[0-9]\..*|441[0-3]" +
                    "\..*|4414\.([0-6]?[0-9]?[0-9]|70[0-5])))).?$",
            string:vers)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  else security_message( port: 0, data: "The target host was found to be vulnerable" );
}

else if(hotfix_check_sp(win2003:3) > 0) {
  vers = get_version(dllPath:dllPath, offs:150000);
  if(vers == NULL){
    exit(0);
  }

  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 1" >< SP) {
    if(ereg(pattern:"^(2000\..*|2001\.(0?[0-9]\..*|1[01]\..*|12\." +
                    "([0-3]?[0-9].*|4[0-6].*|47[01][0-9]\..*|4720" +
                    "\.([0-2]?[0-9]?[0-9]?[0-9]|30.*|31[01][0-9]|" +
                    "312[0-8])))).?$", string:vers)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if("Service Pack 2" >< SP) {
    if(ereg(pattern:"^(2000\..*|2001\.(0?[0-9]\..*|1[01]\..*|12\." +
                    "([0-3]?[0-9].*|4[0-6].*|47[01][0-9]\..*|4720" +
                    "\.([0-3]?[0-9]?[0-9]?[0-9]|4[01].*|42[0-7][0-9]|" +
                    "428[01])))).?$", string:vers)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  else security_message( port: 0, data: "The target host was found to be vulnerable" );
}

dllPath = smb_get_system32root();
if(!dllPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:dllPath, file_name:"Es.dll");
if(dllVer) {
  if(hotfix_check_sp(winVista:2) > 0) {
    SP = get_kb_item("SMB/WinVista/ServicePack");
    if("Service Pack 1" >< SP) {
      if(version_is_less(version:dllVer, test_version:"2001.12.6931.18057")){
        report = report_fixed_ver(installed_version:dllVer, fixed_version:"2001.12.6931.18057", install_path:dllPath);
        security_message(port: 0, data: report);
      }
      exit(0);
    }
  }

  else if(hotfix_check_sp(win2008:2) > 0) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
    if("Service Pack 1" >< SP) {
      if(version_is_less(version:dllVer, test_version:"2001.12.6931.18057")){
          report = report_fixed_ver(installed_version:dllVer, fixed_version:"2001.12.6931.18057", install_path:dllPath);
          security_message(port: 0, data: report);
      }
      exit(0);
    }
  }
}
