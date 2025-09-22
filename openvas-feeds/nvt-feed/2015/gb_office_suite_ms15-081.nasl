# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805087");
  script_version("2024-07-17T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-1642", "CVE-2015-2423", "CVE-2015-2466", "CVE-2015-2467",
                "CVE-2015-2468", "CVE-2015-2469", "CVE-2015-2470", "CVE-2015-2477");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:34:22 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-08-12 14:20:42 +0530 (Wed, 12 Aug 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Suite Remote Code Execution Vulnerabilities (3080790)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-081.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws exist as user supplied input is
  not properly validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to corrupt memory and potentially
  execute arbitrary code.");

  script_tag(name:"affected", value:"- Microsoft Office 2007 Service Pack 3 and prior

  - Microsoft Office 2010 Service Pack 2 and prior

  - Microsoft Office 2013 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2596650");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2687409");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2837610");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3054888");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2598244");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-081");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_office_detection_900025.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007
if(officeVer && officeVer =~ "^12\.")
{
  # Office Word Converter
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
  if(path)
  {
    sysVer = fetch_file_version(sysPath:path + "\Microsoft Office\Office12", file_name:"ieawsdc.dll");
    if(sysVer)
    {
      if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6034.0"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }

  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(dllPath)
  {

    dllVer6 = fetch_file_version(sysPath:dllPath,
                file_name:"Microsoft Shared\VBA\VBA6\VBE6.DLL");
    dllVer  = fetch_file_version(sysPath:dllPath,
                file_name:"Microsoft Shared\OFFICE12\msptls.dll");
    msoVer  =  fetch_file_version(sysPath:dllPath,
                file_name:"Microsoft Shared\OFFICE12\mso.dll");

    if(dllVer6 ||  dllVer ||  msoVer)
    {
      if(version_is_less(version:dllVer6, test_version:"6.5.10.55") ||
         version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6727.4999") ||
         version_in_range(version:msoVer, test_version:"12.0", test_version2:"12.0.6728.4999"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}


## For office 2010 Wwlibcxm.dll is mentioned and it is not available so ignoring
## version check for office 2010 https://support.microsoft.com/en-us/kb/2965311
## MS Office 2010
if(officeVer && officeVer =~ "^14\.")
{
  # Office Word Converter
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
  if(path)
  {
    sysVer = fetch_file_version(sysPath:path + "\Microsoft Office\Office14", file_name:"ieawsdc.dll");
    if(sysVer)
    {
      if(version_in_range(version:sysVer, test_version:"14.0", test_version2:"14.0.6100.0"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }

  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");

  if(dllPath)
  {
    dllVer  = fetch_file_version(sysPath:dllPath, file_name:"Microsoft Shared\OFFICE14\msptls.dll");
    vbVer = fetch_file_version(sysPath:dllPath, file_name:"Microsoft Shared\VBA\VBA7\VBE7.DLL");
    if(dllVer || vbVer)
    {
      if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7155.4999")  ||
         version_in_range(version:vbVer, test_version:"7.0", test_version2:"7.0.16.36"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

## MS Office 2013
if(officeVer && officeVer =~ "^15\.")
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");

  if(dllPath)
  {
    dllVer  = fetch_file_version(sysPath:dllPath, file_name:"Microsoft Shared\OFFICE15\msptls.dll");
    vbVer = fetch_file_version(sysPath:dllPath, file_name:"Microsoft Shared\VBA\VBA7.1\VBEUI.DLL");
    if(dllVer || vbVer)
    {
      if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4745.999")  ||
         version_in_range(version:vbVer, test_version:"7.1", test_version2:"7.1.15.4662"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
