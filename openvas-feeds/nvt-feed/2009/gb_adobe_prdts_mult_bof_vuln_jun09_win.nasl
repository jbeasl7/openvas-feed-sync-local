# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800585");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2009-0198", "CVE-2009-0509", "CVE-2009-0510", "CVE-2009-0511",
                "CVE-2009-0512", "CVE-2009-1855", "CVE-2009-1856", "CVE-2009-1857",
                "CVE-2009-0889", "CVE-2009-0888", "CVE-2009-1858", "CVE-2009-1859",
                "CVE-2009-1861", "CVE-2009-2028");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_name("Adobe Reader/Acrobat Multiple BOF Vulnerabilities (APSB09-07) - Windows");

  script_tag(name:"summary", value:"Adobe Reader/Acrobat is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are reported in Adobe Reader and Acrobat. Please see the references
  for more information.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code to
  cause a stack based overflow via a specially crafted PDF, and could also take
  complete control of the affected system and cause the application to crash.");

  script_tag(name:"affected", value:"Adobe Reader and Acrobat 7 before 7.1.3, 8 before 8.1.6, and 9 before 9.1.2.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader and Acrobat version 9.1.2, 8.1.6 and 7.1.3.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-07.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35274");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35282");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35289");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35291");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35293");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35294");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35295");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35296");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35298");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35299");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35301");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35302");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35303");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1547");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34580");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:acrobat_reader",
                     "cpe:/a:adobe:acrobat");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.1.2") ||
   version_in_range(version:vers, test_version:"8.0", test_version2:"8.1.5") ||
   version_in_range(version:vers, test_version:"9.0", test_version2:"9.1.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.1.2, 8.1.6 or 7.1.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
