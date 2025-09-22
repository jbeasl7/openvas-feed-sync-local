# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teamviewer:teamviewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815860");
  script_version("2025-06-03T05:40:40+0000");
  script_tag(name:"last_modification", value:"2025-06-03 05:40:40 +0000 (Tue, 03 Jun 2025)");
  script_tag(name:"creation_date", value:"2019-12-06 12:34:34 +0530 (Fri, 06 Dec 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-16 19:30:00 +0000 (Mon, 16 Dec 2019)");

  script_cve_id("CVE-2019-19362");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamViewer 'Chat functionality' Information Disclosure Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/detected");

  script_tag(name:"summary", value:"TeamViewer is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to while using Chat functionality, it was
  observed that upon login to Teamviewer desktop application for Windows, it saved every
  communication within Windows main memory. However, while user logs out from account or deletes
  conversation history, under any such case the data would not be wiped from main memory.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to access sensitive
  information.");

  script_tag(name:"affected", value:"TeamViewer version 14.3.4730.");

  script_tag(name:"solution", value:"Update to the latest version available from vendor. Please see
  the references for more information.");

  script_xref(name:"URL", value:"http://nestedif.com/teamviewer-vulnerability-improper-session-handling-leading-to-information-disclosure-advisory/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_equal(version: version, test_version: "14.3.4730")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
