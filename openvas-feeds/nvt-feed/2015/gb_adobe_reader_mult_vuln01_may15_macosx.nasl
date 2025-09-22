# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805385");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-3076", "CVE-2015-3075", "CVE-2015-3074", "CVE-2015-3073",
                "CVE-2015-3072", "CVE-2015-3071", "CVE-2015-3070", "CVE-2015-3069",
                "CVE-2015-3068", "CVE-2015-3067", "CVE-2015-3066", "CVE-2015-3065",
                "CVE-2015-3064", "CVE-2015-3063", "CVE-2015-3062", "CVE-2015-3061",
                "CVE-2015-3060", "CVE-2015-3059", "CVE-2015-3058", "CVE-2015-3057",
                "CVE-2015-3056", "CVE-2015-3055", "CVE-2015-3054", "CVE-2015-3053",
                "CVE-2015-3052", "CVE-2015-3051", "CVE-2015-3050", "CVE-2015-3049",
                "CVE-2015-3048", "CVE-2015-3046", "CVE-2015-3047", "CVE-2014-9160");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-05-15 13:24:05 +0530 (Fri, 15 May 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Reader Multiple Vulnerabilities - 01 (May 2015) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Error 'ScriptBridgeUtils', 'AFParseDate', 'ADBCAnnotEnumerator'
    'WDAnnotEnumerator', 'AFNSimple_Calculate', and 'app.Monitors'.

  - Multiple user-supplied inputs are not properly validated, and an
    use-after-free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct a denial of service, bypass certain security restrictions,
  execute arbitrary code and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Reader 10.x before 10.1.14 and 11.x
  before 11.0.11 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 10.1.14 or
  11.0.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/reader/apsb15-10.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74602");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74602");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74618");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74602");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74602");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74602");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74603");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74601");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74599");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_in_range(version:vers, test_version:"10.0", test_version2:"10.1.13"))
{
  fix = "10.1.14";
  VULN = TRUE ;
}

if(version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.10"))
{
  fix = "11.0.11";
  VULN = TRUE ;
}

if(VULN)
{
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + fix  + '\n';
  security_message(data:report);
  exit(0);
}
