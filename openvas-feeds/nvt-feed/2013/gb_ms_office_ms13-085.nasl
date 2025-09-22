# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903407");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-3889", "CVE-2013-3890");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-10-09 10:10:42 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2885080)");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-085.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Multiple flaws are due to error when processing Microsoft Word binary
  documents can be exploited to cause a memory corruption");

  script_tag(name:"affected", value:"- Microsoft Office 2013

  - Microsoft Office 2007 Service Pack 3 and prior

  - Microsoft Office 2010 Service Pack 2 and prior");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the arbitrary
  code, cause memory corruption and compromise the system.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2760585");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62824");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62829");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2760591");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2826023");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2826035");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2817623");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-085");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

# Microsoft Office 2007 Service Pack 2 and
# Microsoft Office 2010 Service Pack 1 and prior
# Microsoft Office 2013 Service Pack 1 and prior
if(!officeVer || officeVer !~ "^1[245]\."){
  exit(0);
}

foreach offpath (make_list("12.0", "14.0", "15.0"))
{
  comPath = registry_get_sz(key:"SOFTWARE\Microsoft\Office\" + offpath  + "\Access\InstallRoot", item:"Path");
  if(comPath)
  {
    ortVer = fetch_file_version(sysPath:comPath, file_name:"Oart.dll");
    ortconVer = fetch_file_version(sysPath:comPath, file_name:"Oartconv.dll");
    if(!isnull(ortVer) || !isnull(ortconVer))
    {
      if(version_in_range(version:ortVer, test_version:"12.0", test_version2:"12.0.6683.5001") ||
         version_in_range(version:ortconVer, test_version:"12.0", test_version2:"12.0.6683.5001") ||
         version_in_range(version:ortVer, test_version:"14.0", test_version2:"14.0.7108.4999") ||
         version_in_range(version:ortconVer, test_version:"14.0", test_version2:"14.0.7108.4999") ||
         version_in_range(version:ortVer, test_version:"15.0", test_version2:"15.0.4535.1503"))

      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
