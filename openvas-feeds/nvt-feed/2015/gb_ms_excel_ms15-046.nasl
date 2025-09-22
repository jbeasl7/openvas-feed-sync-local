# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805181");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2015-1682", "CVE-2015-1683");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-13 15:24:52 +0530 (Wed, 13 May 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Excel Remote Code Execution Vulnerability (3057181)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-046.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists as user supplied input is
  not properly validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to corrupt memory and potentially
  execute arbitrary code.");

  script_tag(name:"affected", value:"- Microsoft Excel 2010 Service Pack 2 and prior

  - Microsoft Excel 2013 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2965240");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74481");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74484");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2986216");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-046");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^(14|15)\..*")
{
  if(version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.7149.4999") ||
     version_in_range(version:excelVer, test_version:"15.0", test_version2:"15.0.4719.999"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
