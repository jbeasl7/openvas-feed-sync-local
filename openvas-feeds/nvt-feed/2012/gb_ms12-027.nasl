# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902829");
  script_version("2025-03-05T05:38:53+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-0158");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 17:07:11 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-04-11 11:11:11 +0530 (Wed, 11 Apr 2012)");
  script_name("Microsoft Windows Common Controls Remote Code Execution Vulnerability (2664258)");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026904");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52911");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-027");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  # nb: The MSSQL "Consolidation" wasn't added here on purpose and only the SMB Login one was used
  # as the consolidation is not required for the KB check below.
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "gb_microsoft_sql_server_smb_login_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary code
  within the context of the application.");

  script_tag(name:"affected", value:"- Microsoft SQL Server 2008

  - Microsoft Visual Basic 6.0

  - Microsoft Commerce Server 2009

  - Microsoft SQL Server 2005 Service Pack 4

  - Microsoft SQL Server 2000 Service Pack 4

  - Microsoft Visual FoxPro 9.0 Service Pack 2

  - Microsoft Visual FoxPro 8.0 Service Pack 1

  - Microsoft Commerce Server 2007 Service Pack 2

  - Microsoft Commerce Server 2002 Service Pack 4

  - Microsoft Office 2010 Service Pack 1 and prior

  - Microsoft Office 2007 Service Pack 3 and prior

  - Microsoft Office 2003 Service Pack 3 and prior

  - Microsoft SQL Server 2000 Analysis Services Service Pack 4");

  script_tag(name:"insight", value:"The flaw is due to an error within the ListView, ListView2, TreeView
  and TreeView2 ActiveX controls in MSCOMCTL.OCX in the Common Controls and can
  be exploited to corrupt memory.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS12-027.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mscomctl.Ocx");
if(!sysVer){
  exit(0);
}

officeVer = get_kb_item("MS/Office/Ver");

if(officeVer && officeVer =~ "^1[124]\.")
{
  if(version_is_less(version:sysVer, test_version:"6.1.98.33"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

key = "SOFTWARE\Microsoft\BizTalk Server\1.0";
if(registry_key_exists(key:key))
{
  bizName = registry_get_sz(key:key, item:"ProductName");
  if("Microsoft BizTalk Server 2002" >< bizName)
  {
    if(version_is_less(version:sysVer, test_version:"6.1.98.33"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

if(get_kb_item("microsoft/sqlserver/smb-login/detected")) {

  foreach ver (make_list("2005", "10")) {
    key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft SQL Server " + ver;
    if(registry_key_exists(key:key)) {
      if(version_is_less(version:sysVer, test_version:"6.1.98.33")) {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

keys = make_list("SOFTWARE\Microsoft\Commerce Server",
                 "SOFTWARE\Microsoft\Commerce Server 2007",
                 "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"+
                 "\Microsoft Commerce Server 2009");
foreach key (keys)
{
  if(registry_key_exists(key:key))
  {
    if(version_is_less(version:sysVer, test_version:"6.1.98.33"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

key = "SOFTWARE\Microsoft\Visual Basic\6.0";
if(registry_key_exists(key:key))
{
  if(version_is_less(version:sysVer, test_version:"6.1.98.33"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

foreach ver (make_list("8.0", "9.0"))
{
  key = "SOFTWARE\Microsoft\VisualFoxPro\" + ver;
  if(registry_key_exists(key:key))
  {
    if(version_is_less(version:sysVer, test_version:"6.1.98.33"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft SQL " +
      "Server 2000 Analysis Services";
if(registry_key_exists(key:key))
{
  path = registry_get_sz(key:key, item:"InstallLocation");
  dllVer = fetch_file_version(sysPath:path, file_name:"bin\msmdctr80.dll");
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"8.0.2302.0"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft SQL " +
      "Server 2000";
if(registry_key_exists(key:key))
{
  path = registry_get_sz(key:key, item:"InstallLocation");
  exeVer = fetch_file_version(sysPath:path, file_name:"Binn\sqlservr.exe");
  if(exeVer)
  {
    if(version_is_less(version:exeVer, test_version:"2000.80.2065.0") ||
       version_in_range(version:exeVer, test_version:"2000.80.2300.0", test_version2:"2000.80.2300.9"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
