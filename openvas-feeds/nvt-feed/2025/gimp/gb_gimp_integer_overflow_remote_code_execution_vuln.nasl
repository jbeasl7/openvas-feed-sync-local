# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gimp:gimp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836401");
  script_version("2025-08-19T05:39:49+0000");
  script_cve_id("CVE-2025-5473");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-19 05:39:49 +0000 (Tue, 19 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-18 16:00:12 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-06-09 17:40:27 +0530 (Mon, 09 Jun 2025)");
  script_name("GIMP Integer Overflow RCE Vulnerability (Jun 2025) - Windows");

  script_tag(name:"summary", value:"GIMP is prone to an integer overflow remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution.");

  script_tag(name:"affected", value:"GIMP prior to version 3.0.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 3.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-321/");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");

  script_dependencies("gb_gimp_detect.nasl");
  script_mandatory_keys("Gimp/Win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"3.0.4")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "3.0.4", install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);