# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902567");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-1980", "CVE-2011-1982");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2587634)");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026039");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49513");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49519");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-073");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code as
  the logged-on user.");

  script_tag(name:"affected", value:"- Microsoft Office 2003 Service Pack 3

  - Microsoft Office 2007 Service Pack 2

  - Microsoft Office 2010 Service Pack 1 and prior");

  script_tag(name:"insight", value:"- The flaw is due to the application loading libraries in an
    insecure manner when attempting to validate an opened file. This can be
    exploited to load arbitrary libraries by tricking a user into opening a
    PPT file located on a remote WebDAV or SMB share.

  - An error when parsing unspecified data can be exploited to dereference an
    uninitialised value as an object pointer via a specially crafted Word
    document.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-073.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2003, 2007, 2010
if(officeVer && officeVer =~ "^1[124]\.")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
  if(! path) {
    exit(0);
  }

  foreach ver (make_list("OFFICE11", "OFFICE12", "OFFICE14"))
  {
    offPath = path + "\Microsoft Shared\" + ver;
    dllVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");

    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.8340.0")   ||
         version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6562.5002")||
         version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6106.5004"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
