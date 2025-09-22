# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902464");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)");
  script_cve_id("CVE-2011-1972", "CVE-2011-1979");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Visio Remote Code Execution Vulnerabilities (2560978)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553009");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49024");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553010");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553008");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-060");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow users to execute arbitrary code via a
  specially crafted Visio file.");
  script_tag(name:"affected", value:"- Microsoft Visio 2003 Service Pack 3 and prior

  - Microsoft Visio 2007 Service Pack 2 and prior

  - Microsoft Visio 2010 Service Pack 1 and prior");
  script_tag(name:"insight", value:"The flaws are due to an error, while validating of Microsoft Visio
  objects in memory when parsing specially crafted Visio files.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-060.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                             "\App Paths\visio.exe", item:"Path");
## if path is not found exit
if(!sysPath){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"visio.exe");
if(!exeVer){
  exit(0);
}

if(version_in_range(version:exeVer, test_version:"11.0", test_version2:"11.0.8206.0000" ) ||
   version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6556.4999") ||
   version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.6106.4999")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
