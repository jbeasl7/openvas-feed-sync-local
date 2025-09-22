# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803212");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2012-1530", "CVE-2013-0601", "CVE-2013-0602", "CVE-2013-0603",
                "CVE-2013-0604", "CVE-2013-0605", "CVE-2013-0606", "CVE-2013-0607",
                "CVE-2013-0608", "CVE-2013-0609", "CVE-2013-0610", "CVE-2013-0611",
                "CVE-2013-0612", "CVE-2013-0613", "CVE-2013-0614", "CVE-2013-0615",
                "CVE-2013-0616", "CVE-2013-0617", "CVE-2013-0618", "CVE-2013-0619",
                "CVE-2013-0620", "CVE-2013-0621", "CVE-2013-0622", "CVE-2013-0623",
                "CVE-2013-0624", "CVE-2013-0626", "CVE-2013-0627", "CVE-2013-1376");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-01-21 13:16:59 +0530 (Mon, 21 Jan 2013)");
  script_name("Adobe Reader Multiple Vulnerabilities (Jan 2013) - Linux");


  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions, execute arbitrary code in the context of the affected
application or cause a denial of service.");
  script_tag(name:"affected", value:"Adobe Reader versions 9.x to 9.5.2 on Linux");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.5.3 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51791");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57263");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57264");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57265");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57268");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57269");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57270");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57272");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57273");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57274");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57275");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57276");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57277");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57282");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57283");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57284");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57285");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57286");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57287");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57289");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57290");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57291");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57292");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57293");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57294");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57295");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57296");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57297");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65275");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027952");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-02.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^9")
{
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.5.2")){
    report = report_fixed_ver(installed_version:readerVer, vulnerable_range:"9.0 - 9.5.2");
    security_message(port: 0, data: report);
  }
}
