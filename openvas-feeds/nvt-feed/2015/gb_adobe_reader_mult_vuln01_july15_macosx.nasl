# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805680");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2015-5115", "CVE-2015-5114", "CVE-2015-5113", "CVE-2015-5111",
                "CVE-2015-5110", "CVE-2015-5109", "CVE-2015-5108", "CVE-2015-5107",
                "CVE-2015-5106", "CVE-2015-5105", "CVE-2015-5104", "CVE-2015-5103",
                "CVE-2015-5102", "CVE-2015-5101", "CVE-2015-5100", "CVE-2015-5099",
                "CVE-2015-5098", "CVE-2015-5097", "CVE-2015-5096", "CVE-2015-5095",
                "CVE-2015-5094", "CVE-2015-5093", "CVE-2015-5092", "CVE-2015-5091",
                "CVE-2015-5090", "CVE-2015-5089", "CVE-2015-5088", "CVE-2015-5087",
                "CVE-2015-5086", "CVE-2015-5085", "CVE-2015-4452", "CVE-2015-4451",
                "CVE-2015-4450", "CVE-2015-4449", "CVE-2015-4448", "CVE-2015-4447",
                "CVE-2015-4446", "CVE-2015-4445", "CVE-2015-4444", "CVE-2015-4443",
                "CVE-2015-4441", "CVE-2015-4438", "CVE-2015-4435", "CVE-2015-3095",
                "CVE-2014-8450", "CVE-2014-0566");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-07-21 11:27:48 +0530 (Tue, 21 Jul 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Reader Multiple Vulnerabilities - 01 (Jul 2015) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple memory corruption vulnerabilities.

  - Multiple use-after-free vulnerabilities.

  - Multiple integer over flow vulnerabilities.

  - Multiple buffer over flow vulnerabilities.

  - Some unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct a denial of service, bypass certain security restrictions,
  to obtain sensitive information, execute arbitrary code and compromise a
  user's system.");

  script_tag(name:"affected", value:"Adobe Reader 10.x before 10.1.15
  and 11.x before 11.0.12 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 10.1.15 or
  11.0.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75740");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75739");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75746");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75741");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75747");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69825");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75748");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75738");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75743");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75737");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75735");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75749");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75402");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb15-15.html");

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

if(version_in_range(version:vers, test_version:"10.0", test_version2:"10.1.14"))
{
  fix = "10.1.15";
  VULN = TRUE ;
}

if(version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.11"))
{
  fix = "11.0.12";
  VULN = TRUE ;
}

if(VULN)
{
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + fix  + '\n';
  security_message(data:report);
  exit(0);
}




