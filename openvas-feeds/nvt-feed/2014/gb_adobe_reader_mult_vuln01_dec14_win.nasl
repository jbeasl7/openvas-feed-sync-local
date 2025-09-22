# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805303");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-9150", "CVE-2014-9165", "CVE-2014-8445", "CVE-2014-8446",
                "CVE-2014-8447", "CVE-2014-8448", "CVE-2014-8449", "CVE-2014-8451",
                "CVE-2014-8452", "CVE-2014-8453", "CVE-2014-8454", "CVE-2014-8455",
                "CVE-2014-8456", "CVE-2014-8457", "CVE-2014-8458", "CVE-2014-8459",
                "CVE-2014-8461", "CVE-2014-9158", "CVE-2014-9159", "CVE-2014-8460");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-12-11 17:14:05 +0530 (Thu, 11 Dec 2014)");

  script_name("Adobe Reader Multiple Vulnerabilities-01 (Dec 2014) - Windows");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use-after-free errors can be exploited to execute arbitrary code.

  - Multiple unspecified errors can be exploited to cause a heap-based buffer overflow
    and subsequently execute arbitrary code.

  - A Race condition in the MoveFileEx call hook feature allows attackers to
    bypass a sandbox protection mechanism.

  - An error within the implementation of a Javascript API can be exploited to disclose
    certain information.

  - Multiple integer overflow errors can be exploited to execute arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to disclose potentially sensitive information, bypass certain
  security restrictions, execute arbitrary code and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe  Reader 10.x before 10.1.13 and
  Adobe Reader 11.x before 11.0.10 on on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 10.1.13 or
  11.0.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://secunia.com/advisories/61095/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71366");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71557");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71561");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71562");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71564");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71565");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71566");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71567");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71568");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71570");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71571");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71572");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71573");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71574");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71575");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71576");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71577");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71579");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71580");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/reader/apsb14-28.html");
  script_xref(name:"URL", value:"https://code.google.com/p/google-security-research/issues/detail?id=103");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer && readerVer =~ "^1[01]")
{
  if(version_in_range(version:readerVer, test_version:"10.0.0", test_version2:"10.1.12")||
     version_in_range(version:readerVer, test_version:"11.0.0", test_version2:"11.0.9"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
