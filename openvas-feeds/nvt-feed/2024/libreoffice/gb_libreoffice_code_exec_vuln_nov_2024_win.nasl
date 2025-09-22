# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834771");
  script_version("2024-11-26T07:35:52+0000");
  script_cve_id("CVE-2023-6186");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-14 14:41:30 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-11-21 11:59:32 +0530 (Thu, 21 Nov 2024)");
  script_name("LibreOffice Code Execution Vulnerability (Nov 2024) - Windows");

  script_tag(name:"summary", value:"LibreOffice is prone to a code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  macro permission validation in the document foundation LibreOffice.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary scripts or commands through specially crafted hyperlinks
  embedded in documents.");

  script_tag(name:"affected", value:"LibreOffice version 7.5.0 before 7.5.9 and
  7.6.0 before 7.6.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 7.5.9 or 7.6.4 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2023-6186/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_libre_office_detect_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range_exclusive(version:vers, test_version_lo:"7.5.0", test_version_up:"7.5.9")) {
  fix = "7.5.9";
}
else if(version_in_range_exclusive(version:vers, test_version_lo:"7.6.0", test_version_up:"7.6.4")) {
  fix = "7.6.4";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
