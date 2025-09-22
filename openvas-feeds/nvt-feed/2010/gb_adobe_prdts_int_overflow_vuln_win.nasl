# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801419");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2862");
  script_name("Adobe Reader/Acrobat Font Parsing Integer Overflow Vulnerability (CVE-2010-2862) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40766");
  script_xref(name:"URL", value:"http://www.zdnet.co.uk/news/security-threats/2010/08/04/adobe-confirms-pdf-security-hole-in-reader-40089737/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation results in memory corruption via a PDF
  file containing a specially crafted TrueType font.");

  script_tag(name:"affected", value:"Adobe Reader version 8.2.3 and 9.3.3

  Adobe Acrobat version 9.3.3 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an integer overflow error in 'CoolType.dll'
  when parsing the 'maxCompositePoints' field value in the 'maxp' (Maximum Profile)
  table of a TrueType font.");

  script_tag(name:"solution", value:"Upgrade to version 8.2.4 or 9.3.4 or later.");

  script_tag(name:"summary", value:"Adobe products are prone to a font parsing integer overflow vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
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
cpe  = infos["cpe"];

if(cpe == "cpe:/a:adobe:acrobat_reader") {
  if(version_is_less_equal(version:vers, test_version:"8.2.3") ||
     version_in_range(version:vers, test_version:"9.0", test_version2:"9.3.3")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"8.2.4 or 9.3.4", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
} else if(cpe == "cpe:/a:adobe:acrobat") {
  if(version_is_less_equal(version:vers, test_version:"9.3.3")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"9.3.4", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
