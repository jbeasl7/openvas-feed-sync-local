# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902400");
  script_version("2025-03-05T05:38:52+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2011-0609");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 14:20:56 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_name("Adobe Products Remote Memory Corruption Vulnerability (APSA11-01) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat, Adobe Reader or Adobe Flash Player is prone to a
  memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in handling 'SWF' file in adobe flash player and
  'Authplay.dll' in Adobe acrobat/reader. which allows attackers to execute
  arbitrary code or cause a denial of service via crafted flash content.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to corrupt memory and execute
  arbitrary code on the system with elevated privileges.");

  script_tag(name:"affected", value:"Adobe Flash Player version 10.2.152.33 and prior on Windows.

  Adobe Reader/Acrobat version 9.x to 9.4.2 and 10.x to 10.0.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player to 10.2.153.1 or later and upgrade
  Adobe Reader/Acrobat to 10.0.2.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-06.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46860");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa11-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
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
  if(version_in_range(version:vers, test_version:"9.0", test_version2:"9.4.2") ||
     version_in_range(version:vers, test_version:"10.0", test_version2:"10.0.1")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"10.0.2", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
} else if(cpe == "cpe:/a:adobe:flash_player") {
  if(version_is_less_equal(version:vers, test_version:"10.2.152.33")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"10.2.153.1", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
