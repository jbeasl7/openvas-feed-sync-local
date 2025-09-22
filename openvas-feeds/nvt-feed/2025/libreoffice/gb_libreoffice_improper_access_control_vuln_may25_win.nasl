# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836193");
  script_version("2025-05-09T05:40:06+0000");
  script_cve_id("CVE-2023-2255");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-01 17:34:36 +0000 (Thu, 01 Jun 2023)");
  script_tag(name:"creation_date", value:"2025-05-08 16:53:31 +0530 (Thu, 08 May 2025)");
  script_name("LibreOffice Improper Access Control vulnerability (May 2025) - Windows");

  script_tag(name:"summary", value:"LibreOffice is prone to an improper access
  control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to bypass security restrictions and disclose information.");

  script_tag(name:"affected", value:"LibreOffice prior to version 7.4.7 and 7.5.x
  before 7.5.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 7.4.7 or 7.5.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2023-2255/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_libre_office_detect_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"7.4.7")) {
  fix = "7.4.7";
}

if(version_in_range_exclusive(version:version, test_version_lo:"7.5", test_version_up:"7.5.3")) {
  fix = "7.5.3.";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);