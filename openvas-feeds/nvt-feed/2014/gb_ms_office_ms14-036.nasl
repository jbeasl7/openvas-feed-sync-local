# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804460");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-1817", "CVE-2014-1818");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-11 12:17:32 +0530 (Wed, 11 Jun 2014)");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2967487)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS14-036.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error within Unicode Scripts Processor can be exploited to execute
  arbitrary code via a specially crafted font file.

  - An error within GDI+ when validating images can be exploited to execute
  arbitrary code via a specially crafted image file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the currently logged-in user, which may lead to a complete compromise of an affected computer.");

  script_tag(name:"affected", value:"- Microsoft Office 2007 Service Pack 2

  - Microsoft Office 2010 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2878233");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67897");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67904");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2863942");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2767915");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2881069");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-036");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-036");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007/2010
if(!officeVer || officeVer !~ "^1[24]\."){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
if(path)
{
  foreach ver (make_list("OFFICE12", "OFFICE14"))
  {
    offPath = path + "\Microsoft Shared\" + ver;
    dllVer = fetch_file_version(sysPath:offPath, file_name:"Ogl.dll");

    if(dllVer &&
       (version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7125.4999") ||
        version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6700.4999")))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}


## MS Office 2010
if(officeVer && officeVer =~ "^1[24]\.")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
  if(!path)
  {
    foreach ver (make_list("OFFICE12", "OFFICE14"))
    {
      msPath = path  +  "\Microsoft Shared\" + ver;
      dllVer = fetch_file_version(sysPath:msPath, file_name:"Usp10.dll");
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"1.0626.7601.00000", test_version2:"1.0626.7601.22665") ||
           version_in_range(version:dllVer, test_version:"1.0626.6002.00000", test_version2:"1.0626.6002.23385"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}
