# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808167");
  script_version("2024-02-12T05:05:32+0000");
  script_cve_id("CVE-2016-4126");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-26 19:19:00 +0000 (Fri, 26 Nov 2021)");
  script_tag(name:"creation_date", value:"2016-06-17 10:47:28 +0530 (Fri, 17 Jun 2016)");
  script_name("Adobe Air Security Update (APSB16-23) - Windows");

  script_tag(name:"summary", value:"Adobe Air is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  directory search path used by the AIR installer that could potentially allow
  an attacker to take control of the affected system.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct code execution.");

  script_tag(name:"affected", value:"Adobe Air version before version 22.0.0.153.");

  script_tag(name:"solution", value:"Update to version 22.0.0.153 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/air/apsb16-23.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"22.0.0.153")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"22.0.0.153", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
