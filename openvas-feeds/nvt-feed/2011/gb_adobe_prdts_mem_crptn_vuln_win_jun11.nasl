# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902379");
  script_version("2025-03-05T05:38:52+0000");
  script_cve_id("CVE-2011-2103");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_name("Adobe Reader/Acrobat Memory Corruption Vulnerability (APSB11-16) - Windows");

  script_tag(name:"summary", value:"Adobe Reader/Acrobat is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error, which leads to memory corruption.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code in the context
  of the user running the affected application.");

  script_tag(name:"affected", value:"Adobe Reader version 8.x through 8.2.6

  Adobe Acrobat version 8.x through 8.2.6");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat and Reader version 8.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-16.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48247");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
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

if(version_in_range(version:vers, test_version:"8.0", test_version2:"8.2.6")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"8.0 - 8.2.6", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
