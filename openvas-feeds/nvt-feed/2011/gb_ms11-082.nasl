# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902580");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-10-12 16:01:32 +0200 (Wed, 12 Oct 2011)");
  script_cve_id("CVE-2011-2007", "CVE-2011-2008");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Microsoft Host Integration Server Denial of Service Vulnerabilities (2607670)");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026168");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49997");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49998");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-082");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause the application
  to become unresponsive or to crash, denying service to legitimate users.");

  script_tag(name:"affected", value:"- Microsoft Host Integration for Microsoft Windows Server 2009/2010

  - Microsoft Host Integration for Microsoft Windows Server 2006 SP1 and prior

  - Microsoft Host Integration for Microsoft Windows Server 2004 SP1 and prior");

  script_tag(name:"insight", value:"Multiple flaws are due to input validation errors when processing
  certain requests can be exploited to trigger an infinite loop, corrupt
  memory and cause the snabase.exe, snaserver.exe, snalink.exe, or
  mngagent.exe process to stop responding via specially crafted requests
  sent to UDP port 1478 or TCP ports 1477 and 1478.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-082.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## MS11-082 Hotfix
if((hotfix_missing(name:"2578757") == 0) || (hotfix_missing(name:"2579597") == 0) ||
   (hotfix_missing(name:"2579598") == 0) || (hotfix_missing(name:"2579599") == 0)){
  exit(0);
}

key = "SOFTWARE\Microsoft\Host Integration Server\ConfigFramework";
if(!registry_key_exists(key:key)){
  exit(0);
}

path = registry_get_sz(key:key, item:"Path");
if(!path) {
  exit(0);
}

dllVer = fetch_file_version(sysPath:path, file_name:"system\Snadmod.dll");
if(!dllVer){
  exit(0);
}

if(version_in_range(version:dllVer, test_version:"6.0", test_version2:"6.0.2444.9") ||
   version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.4219.9") ||
   version_in_range(version:dllVer, test_version:"8.0", test_version2:"8.0.3850.0") ||
   version_in_range(version:dllVer, test_version:"8.0.3870", test_version2:"8.0.3872.1") ||
   version_in_range(version:dllVer, test_version:"8.5", test_version2:"8.5.4317.0") ||
   version_in_range(version:dllVer, test_version:"8.5.4360", test_version2:"8.5.4369.1")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
