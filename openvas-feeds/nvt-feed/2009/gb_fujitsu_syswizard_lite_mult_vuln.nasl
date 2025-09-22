# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900456");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-01-30 14:33:42 +0100 (Fri, 30 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0264", "CVE-2009-0270", "CVE-2009-0271");
  script_name("FUJITSU SystemWizard Lite Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33594");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33344");
  script_xref(name:"URL", value:"http://securityvulns.com/Vdocument198.html");
  script_xref(name:"URL", value:"http://www.wintercore.com/advisories/advisory_W010109.html");
  script_xref(name:"URL", value:"http://primeserver.fujitsu.com/primequest/products/os/windows2008.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes via
  a large PXE protocol request in a UDP packet and also directory traversal
  attack sequences in unspecified vectors.");

  script_tag(name:"affected", value:"FUJITSU SystemWizard Lite version 2.0A and prior on Windows.");

  script_tag(name:"insight", value:"Improper boundary check of input data in DefaultSkin.ini in TFTP service,
  Registry Setting Tool and PXEService.exe files.");

  script_tag(name:"solution", value:"Apply the security patches from the linked references.");

  script_tag(name:"summary", value:"FUJITSU SystemWizard Lite is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\FUJITSU")){
  exit(0);
}

key = "SOFTWARE\FUJITSU\SystemcastWizard";
fuziVer = registry_get_sz(key:"SOFTWARE\FUJITSU\SystemcastWizard",
                          item:"ProductVersion");
if(!fuziVer){
  exit(0);
}

wizardVer =  eregmatch(pattern:"V([0-9.]+A?)", string:fuziVer);
if(wizardVer[1] == NULL){
  exit(0);
}

if(version_is_less_equal(version:wizardVer[1], test_version:"1.6A"))
{
  report = report_fixed_ver(installed_version:wizardVer[1], vulnerable_range:"Less than or equal to 1.6A");
  security_message(port: 0, data: report);
  exit(0);
}

if(version_is_less_equal(version:wizardVer[1], test_version:"2.0A"))
{
  key = "SOFTWARE\FUJITSU\SystemcastWizard";
  path = registry_get_sz(key:key, item:"InstallPath");
  if(!path){
    exit(0);
  }

  dllPath = path + "bin\ChkPXESv.dll";
  share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:dllPath);

  dllVer = GetVer(share:share, file:file);
  if(!dllVer){
    exit(0);
  }

  if(version_is_less(version:dllVer, test_version:"4.0.11.530")){
    report = report_fixed_ver(installed_version:dllVer, fixed_version:"4.0.11.530", install_path:dllPath);
    security_message(port: 0, data: report);
  }
}
