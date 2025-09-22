# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902996");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-1315", "CVE-2013-3158", "CVE-2013-3159");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-09-11 12:29:56 +0530 (Wed, 11 Sep 2013)");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2858300) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-073.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"insight", value:"Multiple flaws exist when processing XML data, which can be exploited to
  disclose contents of certain local files by sending specially crafted XML data including external entity references.");

  script_tag(name:"affected", value:"Microsoft Office 2011 on Mac OS X.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to corrupt memory and
  disclose sensitive information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-073");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62167");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62219");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62225");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

offVer = get_kb_item("MS/Office/MacOSX/Ver");

if(!offVer || offVer !~ "^14\."){
  exit(0);
}

if(version_in_range(version:offVer, test_version:"14.0", test_version2:"14.3.6"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
