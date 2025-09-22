# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803415");
  script_version("2024-07-17T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0640", "CVE-2013-0641");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:36:05 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-02-19 18:24:49 +0530 (Tue, 19 Feb 2013)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities -01 (Feb 2013) - Windows");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are due to unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code or cause
a denial of service via a crafted PDF document.");
  script_tag(name:"affected", value:"Adobe Reader Version 9.x prior to 9.5.4 on Windows

Adobe Reader X Version 10.x prior to 10.1.6 on Windows

Adobe Reader XI Version 11.x prior to 11.0.02 on Windows");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.5.4, 10.1.6, 11.0.02 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52196");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57931");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57947");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa13-02.html");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2013/02/adobe-reader-and-acrobat-vulnerability-report.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if(readerVer =~ "^(9|10|11)")
{
  if((version_in_range(version:readerVer, test_version:"9.0", test_version2: "9.5.3"))||
     (version_in_range(version:readerVer, test_version:"10.0", test_version2: "10.1.5"))||
     (version_in_range(version:readerVer, test_version:"11.0", test_version2: "11.0.01")))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
