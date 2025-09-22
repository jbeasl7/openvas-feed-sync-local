# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805025");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-6356", "CVE-2014-6357");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-12-10 12:08:06 +0530 (Wed, 10 Dec 2014)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerabilities (3017301)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS14-081.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to:

  - An invalid indexing error when parsing Office files can be exploited to
    execute arbitrary code via a specially crafted Office file.

  - A use-after-free error when parsing Office files can be exploited to execute
    arbitrary code via a specially crafted Office file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute the arbitrary code, cause memory corruption and
  compromise the system.");

  script_tag(name:"affected", value:"- Microsoft Word 2007 SP3 and prior

  - Microsoft Word 2010 Service Pack 2 and prior

  - Microsoft Word 2013 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3017301");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71470");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-081");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  exit(0);
}


include("version_func.inc");

winwordVer = get_kb_item("SMB/Office/Word/Version");

## Microsoft Office Word 2007
if(winwordVer && winwordVer =~ "^(12|14|15).*")
{
  ## 15 < 15.0.4675.1000
  if(version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6713.4999") ||
     version_in_range(version:winwordVer, test_version:"14.0", test_version2:"14.0.7140.4999") ||
     version_in_range(version:winwordVer, test_version:"15.0", test_version2:"15.0.4675.999"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
