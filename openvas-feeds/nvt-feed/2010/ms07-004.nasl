# SPDX-FileCopyrightText: 2010 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102053");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)");
  script_cve_id("CVE-2007-0024");
  script_name("Microsoft Windows Vector Markup Language Vulnerabilities (929969)");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/122084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21930");
  script_xref(name:"URL", value:"http://secunia.com/advisories/23677");
  script_xref(name:"URL", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=462");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-004");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Remote exploitation of an integer overflow vulnerability in the
  Vector Markup Language (VML) support in multiple Microsoft products allows attackers to execute
  arbitrary code within the context of the user running the vulnerable application.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0)
  exit(0);

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer)
  exit(0);

# MS07-033 Hotfix (929969)
if(hotfix_missing(name:"929969") == 0)
  exit(0);

dllPath = registry_get_sz(item:"CommonFilesDir", key:"SOFTWARE\Microsoft\Windows\CurrentVersion");
dllPath += "\Microsoft Shared\VGX\vgx.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

vers = GetVer(file:file, share:share);
if(!vers)
  exit(0);

# CVE-2007-0024
if(hotfix_check_sp(win2k:5) > 0) {

  #Vgx.dll 5.0.3848.1800
  SP = get_kb_item("SMB/Win2K/ServicePack");
  if("Service Pack 4" >< SP) {
    if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1588")) {
      security_message(port:0, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }
}

else if(hotfix_check_sp(xp:4) > 0) {
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP) {
    if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2900.3051") ||
       version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16386")) {
      security_message(port:0, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }
}

else if(hotfix_check_sp(win2003:3) > 0) {
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 1" >< SP) {
    if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.2851") ||
       version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16386")) {
      security_message(port:0, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }
}

exit(99);
