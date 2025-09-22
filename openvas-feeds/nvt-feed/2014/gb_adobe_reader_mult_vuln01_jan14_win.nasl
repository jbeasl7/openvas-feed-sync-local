# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804068");
  script_version("2024-02-09T05:06:25+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0493", "CVE-2014-0495", "CVE-2014-0496");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-01-21 12:29:20 +0530 (Tue, 21 Jan 2014)");
  script_name("Adobe Reader Multiple Vulnerabilities - 01 (Jan 2014) - Windows");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to some unspecified errors and an error in dereferencing already
freed memory.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to, execute arbitrary code and
compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Reader X Version 10.x prior to 10.1.9 on Windows

Adobe Reader XI Version 11.x prior to 11.0.06 on Windows");
  script_tag(name:"solution", value:"Update to Adobe Reader Version 10.1.9 or 11.0.06 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56303");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64802");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64803");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64804");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/acrobat/apsb14-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers && vers =~ "^1[01]\.") {
  if((version_in_range(version:vers, test_version:"10.0", test_version2: "10.1.8"))||
     (version_in_range(version:vers, test_version:"11.0", test_version2: "11.0.05")))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
