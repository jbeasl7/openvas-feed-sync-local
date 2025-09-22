# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836571");
  script_version("2025-08-08T05:44:56+0000");
  script_cve_id("CVE-2022-38745");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-08 05:44:56 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-28 21:37:15 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"creation_date", value:"2025-08-07 13:18:33 +0530 (Thu, 07 Aug 2025)");
  script_name("Libre Office Arbitrary Code Execution vulnerability (Aug 2025) - Linux");

  script_tag(name:"summary", value:"Libre Office is prone to an arbitrary code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform arbitrary code execution.");

  script_tag(name:"affected", value:"Libre Office prior to version 7.2.6 and
  7.3.x before 7.3.1 on Linux.");

  script_tag(name:"solution", value:"Update to version 7.2.6 or 7.3.1 later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2022-38745/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_libre_office_detect_lin.nasl");
  script_mandatory_keys("LibreOffice/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

libre_ver = infos["version"];
libre_path = infos["location"];

if(version_is_less(version:libre_ver, test_version:"7.2.6")) {
  fix = "7.2.6";
}

if(version_in_range_exclusive(version:libre_ver, test_version_lo: "7.3", test_version_up: "7.3.1")) {
  fix = "7.3.1";
}

if(fix) {
  report = report_fixed_ver(installed_version:libre_ver, fixed_version:fix, install_path:libre_path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);