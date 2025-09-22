# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902430");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-05-11 14:45:15 +0200 (Wed, 11 May 2011)");
  script_cve_id("CVE-2011-1269", "CVE-2011-1270");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2545814)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2535802");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2535812");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2535818");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2540162");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1201");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/PowerPnt/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a malicious PPT file.");

  script_tag(name:"affected", value:"- Microsoft PowerPoint 2007 Converter

  - Microsoft PowerPoint 2002 Service Pack 3

  - Microsoft PowerPoint 2003 Service Pack 3

  - Microsoft PowerPoint 2007 Service Pack 2");

  script_tag(name:"insight", value:"The flaws are due to a memory corruption and buffer overflow error
  when parsing a malformed PowerPoint file, which could be exploited to execute
  arbitrary code via a malicious document.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-036.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-036");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

if(!officeVer || officeVer !~ "^1[0-2]\."){
  exit(0);
}

pptVer = get_kb_item("SMB/Office/PowerPnt/Version");
if(pptVer && pptVer =~ "^1[0-2]\.") {
  if(version_in_range(version:pptVer, test_version:"10.0", test_version2:"10.0.6871.0") ||
     version_in_range(version:pptVer, test_version:"11.0", test_version2:"11.0.8334.0") ||
     version_in_range(version:pptVer, test_version:"12.0", test_version2:"12.0.6545.4999"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# Office PowerPoint 2007 converter
if(registry_key_exists(key:"SOFTWARE\Microsoft\Office"))
{
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
  if(sysPath)
  {
    dllVer = fetch_file_version(sysPath:sysPath, file_name:"Microsoft Office\Office12\Ppcnv.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6557.5000")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
