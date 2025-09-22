# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819943");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2021-45057", "CVE-2021-45058", "CVE-2021-45059");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-15 03:41:00 +0000 (Sat, 15 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-13 18:55:36 +0530 (Thu, 13 Jan 2022)");
  script_name("Adobe InDesign Multiple Vulnerabilities (APSB22-05) - Mac OS X");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe January update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An Use After Free error.

  - Multiple Out-of-bounds Write errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and escalate privilege on an affected system.");

  script_tag(name:"affected", value:"Adobe InDesign 16.4 and earlier versions on Mac OS X.");

  script_tag(name:"solution", value:"Update Adobe InDesign to version 16.4.1 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb22-05.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_indesign_server_detect_macosx.nasl");
  script_mandatory_keys("InDesign/Server/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"16.4.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"16.4.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
