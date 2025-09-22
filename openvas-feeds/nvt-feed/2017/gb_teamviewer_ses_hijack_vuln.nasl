# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:teamviewer:teamviewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107273");
  script_version("2024-11-27T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-11-27 05:05:40 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-12-11 09:50:38 +0700 (Mon, 11 Dec 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Teamviewer Session Hijacking Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/detected");

  script_tag(name:"summary", value:"Teamviewer is vulnerable to session hijacking.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused through an injectable C++ DLL which takes
  advantage of the bug to change TeamViewer permissions");

  script_tag(name:"impact", value:"Successful exploitation can give local users power over another
  system involved in a session and seize control of PCs through desktop sessions.");

  script_tag(name:"affected", value:"Teamviewer versions prior to 13.0.5640.0.");

  script_tag(name:"solution", value:"Update to version 13.0.5640.0.");

  script_xref(name:"URL", value:"http://www.zdnet.com/article/teamviewer-issues-emergency-fix-for-remote-access-vulnerability/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "13.0.5640.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.0.5640.0", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
