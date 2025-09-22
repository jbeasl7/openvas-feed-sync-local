# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802864");
  script_version("2025-08-05T05:45:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-1889");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 14:18:20 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-06-14 12:09:11 +0530 (Thu, 14 Jun 2012)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft XML Core Services Remote Code Execution Vulnerability (2719615)");

  script_tag(name:"summary", value:"Microsoft XML Core Services is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Microsoft XML Core Services attempts to access
  an object in memory that has not been initialized, which allows  an attacker to
  corrupt memory.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote
  attackers to execute arbitrary code as the logged-on user.");

  script_tag(name:"affected", value:"- Microsoft Expression Web 2

  - Microsoft Office Word Viewer

  - Microsoft Office Compatibility

  - Microsoft Office 2003 Service Pack 3 and prior

  - Microsoft Office 2007 Service Pack 3 and prior

  - Microsoft Expression Web Service Pack 1 and prior

  - Microsoft Groove Server 2007 Service Pack 3 and prior

  - Microsoft SharePoint Server 2007 Service Pack 3 and prior

  - Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://securitytracker.com/id/1027157");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2719615");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2012/2719615");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-043");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_office_products_version_900032.nasl",
                      "gb_microsoft_sharepoint_smb_login_detect.nasl", "gb_ms_expression_web_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2) <= 0)
{
  exit(0);
}

sysPath = smb_get_systemroot();
if(! sysPath){
   exit(0);
}

dllVer3 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml3.dll");

if(dllVer3)
{
  if(hotfix_check_sp(xp:4) > 0)
  {
    if(version_is_less(version:dllVer3, test_version:"8.100.1053.0"))
    {
      Vulnerable_range = "Version Less than - 8.100.1053.0";
      VULN = TRUE ;
    }
  }

  else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
  {
     if(version_is_less(version:dllVer3, test_version:"8.100.1052.0"))
     {
       Vulnerable_range = "Version Less than - 8.100.1052.0";
       VULN = TRUE ;
     }
  }

  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:dllVer3, test_version:"8.100.5005.0"))
    {
      Vulnerable_range = "Version Less than - 8.100.5005.0";
      VULN = TRUE ;
    }
  }

  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_is_less(version:dllVer3, test_version:"8.110.7600.17036")){
      Vulnerable_range = "Version Less than - 8.110.7600.17036";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"8.110.7600.20000", test_version2:"8.110.7600.21226")){
      Vulnerable_range = "8.110.7600.20000 - 8.110.7600.21226";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"8.110.7601.17000", test_version2:"8.110.7601.17856")){
      Vulnerable_range = "8.110.7601.17000 - 8.110.7601.17856";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer3, test_version:"8.110.7601.21000", test_version2:"8.110.7601.22011"))
    {
      Vulnerable_range = "8.110.7601.21000 - 8.110.7601.22011";
      VULN = TRUE ;
    }
  }
  dllVer = dllVer3 ;
  location = sysPath + "\system32\Msxml3.dll";
}

dllVer4 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml4.dll");

if(dllVer4)
{
  if(version_is_less(version:dllVer4, test_version:"4.30.2114.0"))
  {
    dllVer = dllVer4 ;
    Vulnerable_range = "Version Less than - 4.30.2114.0";
    location = sysPath + "\system32\Msxml4.dll";
    VULN = TRUE ;
  }
}

dllVer6 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml6.dll");

dllVer6 = fetch_file_version(sysPath:sysPath, file_name:"system32\Msxml6.dll");
if(dllVer6)
{
  if(hotfix_check_sp(xp:4) > 0)
  {
    if(version_is_less(version:dllVer6, test_version:"6.20.2501.0"))
    {
      Vulnerable_range = "Version Less than - 6.20.2501.0";
      VULN = TRUE ;
    }
  }

  else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
  {
    if(version_is_less(version:dllVer6, test_version:"6.20.2012.0"))
    {
      Vulnerable_range = "Version Less than - 6.20.2012.0";
      VULN = TRUE ;
    }
  }

  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:dllVer6, test_version:"6.20.5005.0"))
    {
      Vulnerable_range = "Version Less than - 6.20.5005.0";
      VULN = TRUE ;
    }
  }

  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_is_less(version:dllVer6, test_version:"6.30.7600.17036")){
      Vulnerable_range = "Version Less than - 6.30.7600.17036";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer6, test_version:"6.30.7600.20000", test_version2:"6.30.7600.21226")){
      Vulnerable_range = "6.30.7600.20000 - 6.30.7600.21226";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer6, test_version:"6.30.7601.17000", test_version2:"6.30.7601.17856")){
      Vulnerable_range = "6.30.7601.17000 - 6.30.7601.17856";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer6, test_version:"6.30.7601.21000", test_version2:"6.30.7601.22011")){
      Vulnerable_range = "6.30.7601.21000 - 6.30.7601.22011";
      VULN = TRUE ;
    }
  }

  dllVer = dllVer6;
  location = sysPath + "\system32\Msxml6.dll";
}

if(VULN)
{
  report = 'File checked:     ' + location + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

officeVer = get_kb_item("MS/Office/Ver");
wordVer = get_kb_item("SMB/Office/Word/Version");
wordCnvVer = get_kb_item("SMB/Office/WordCnv/Version");
grooveVer = get_kb_item("SMB/Office/Groove/Version");
shrPtSrvVer = get_kb_item("microsoft/sharepoint/server/smb-login/version");
expressWebVer = get_kb_item("MS/Expression-Web/Ver");

## Groove server 2007 , Sharepoint Server 2007
if((officeVer && officeVer =~ "^1[12]\.") ||
   wordVer || wordCnvVer ||
   (grooveVer && grooveVer =~ "^12\.") ||
   (shrPtSrvVer && shrPtSrvVer =~ "^12\.") ||
   (expressWebVer && expressWebVer =~ "^12\."))
{
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(! sysPath){
    exit(0);
  }

  foreach ver (make_list("OFFICE11", "OFFICE12"))
  {
    sysPath = sysPath + "\Microsoft Shared\" + ver ;

    dllVer5 = fetch_file_version(sysPath:sysPath, file_name:"Msxml5.dll");

    if(! dllVer5){
     continue;
    }

    if(version_is_less(version:dllVer5, test_version:"5.20.1096.0"))
    {
      report = 'File checked:     ' + sysPath + "\system32\Msxml5.dll" + '\n' +
               'File version:     ' + dllVer5  + '\n' +
               'Vulnerable range: Version Less than - 5.20.1096.0 \n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
