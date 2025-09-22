# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836062");
  script_version("2025-03-25T05:38:56+0000");
  script_cve_id("CVE-2021-25635");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-03-25 05:38:56 +0000 (Tue, 25 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-24 22:16:25 +0530 (Mon, 24 Mar 2025)");
  script_name("LibreOffice Improper Certificate Validation Vulnerability (Mar 2025) - Windows");

  script_tag(name:"summary", value:"LibreOffice is prone to an improper
  certificate validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper
  certificate validation in LibreOffice's digital signature verification
  process.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to self-sign an ODF document with a signature untrusted by the target, then
  modify it by changing the signature algorithm to an invalid one.");

  script_tag(name:"affected", value:"LibreOffice version 7.0 before 7.0.5 and
  7.1 before 7.1.1 on Windows.");

  script_tag(name:"solution", value:"Update to version 7.0.5 or 7.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2021-25635/");
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

if(version_in_range_exclusive(version:version, test_version_lo:"7.0", test_version_up:"7.0.5")) {
  fix = "7.0.5";
}

if(version_in_range_exclusive(version:version, test_version_lo:"7.1", test_version_up:"7.1.1")) {
  fix = "7.1.1.";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);