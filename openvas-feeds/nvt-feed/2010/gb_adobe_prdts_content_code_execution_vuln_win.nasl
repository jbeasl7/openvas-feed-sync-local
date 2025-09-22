# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902303");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2010-2884");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");

  script_name("Adobe Products Content Code Execution Vulnerability (APSA10-03) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat, Adobe Reader or Adobe Flash Player is prone to a
  code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by an unspecified error when processing
  malformed 'Flash' or '3D' and 'Multimedia' content within a PDF document, which could be exploited
  by attackers to execute arbitrary code by convincing a user to open a specially crafted PDF
  file.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to corrupt memory and
  execute arbitrary code on the system with elevated privileges.");

  script_tag(name:"affected", value:"- Adobe Reader/Acrobat versions 9.3.4 and prior

  - Adobe Flash Player versions 10.1.82.76 and prior");

  script_tag(name:"solution", value:"- Update to Adobe Flash version 10.1.85.3 or later

  - Update to Adobe Reader/Acrobat version 9.4 or later");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61771");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43205");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2349");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2348");
  script_xref(name:"URL", value:"https://www.adobe.com/support/security/advisories/apsa10-03.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl", "gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:acrobat_reader",
                     "cpe:/a:adobe:acrobat",
                     "cpe:/a:adobe:flash_player");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if(cpe == "cpe:/a:adobe:acrobat_reader" || cpe == "cpe:/a:adobe:acrobat") {
  if(version_is_less_equal(version:vers, test_version:"9.3.4")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"9.3.4", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
} else if(cpe == "cpe:/a:adobe:flash_player") {
  if(version_is_less_equal(version:vers, test_version:"10.1.82.76")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"10.1.85.3", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
