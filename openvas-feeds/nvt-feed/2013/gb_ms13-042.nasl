# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902970");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-1316", "CVE-2013-1317", "CVE-2013-1318", "CVE-2013-1319",
                "CVE-2013-1320", "CVE-2013-1321", "CVE-2013-1322", "CVE-2013-1323",
                "CVE-2013-1327", "CVE-2013-1328", "CVE-2013-1329");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-05-15 10:32:57 +0530 (Wed, 15 May 2013)");
  script_name("Microsoft Office Publisher Remote Code Execution Vulnerability (2830397)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2810047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59761");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59762");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59763");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59764");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59766");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59767");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59768");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59769");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59771");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59772");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2597971");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553147");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-042");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "gb_smb_windows_detect.nasl");
  script_mandatory_keys("SMB/Office/Publisher/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted publisher files.");

  script_tag(name:"affected", value:"- Microsoft Publisher 2003 Service Pack 3 and prior

  - Microsoft Publisher 2007 Service Pack 3 and prior

  - Microsoft Publisher 2010 Service Pack 1 and prior");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An unspecified errors when handling array size, return values,
  table range data, NULL values.

  - An integer overflow vulnerability exists.

  - A signedness error exists when parsing certain data, which can be
  exploited to corrupt memory.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-042.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

pubVer = get_kb_item("SMB/Office/Publisher/Version");
if(pubVer && pubVer =~ "^1[124]\.")
{
  if(version_in_range(version:pubVer, test_version:"11.0",test_version2:"11.0.8401") ||
     version_in_range(version:pubVer, test_version:"12.0",test_version2:"12.0.6676.4999")||
     version_in_range(version:pubVer, test_version:"14.0",test_version2:"14.0.6137.4999"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
