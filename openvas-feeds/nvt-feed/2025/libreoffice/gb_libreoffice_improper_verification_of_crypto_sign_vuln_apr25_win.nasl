# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836168");
  script_version("2025-07-04T05:42:00+0000");
  script_cve_id("CVE-2025-2866");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-07-04 05:42:00 +0000 (Fri, 04 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-03 21:26:26 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-04-28 10:49:32 +0530 (Mon, 28 Apr 2025)");
  script_name("LibreOffice Improper Verification of Cryptographic Signature Vulnerability (Apr 2025) - Windows");

  script_tag(name:"summary", value:"LibreOffice is prone to an improper
  verification of cryptographic signature vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to incomplete validation
  of digital signatures using the adbe.pkcs7.sha1 SubFilter.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to spoof trusted PDF signatures, leading to possible document forgery and
  loss of trust in signed PDFs.");

  script_tag(name:"affected", value:"LibreOffice prior to version 24.8.6 and
  25.x before 25.2.2 on Windows.");

  script_tag(name:"solution", value:"Update to version 24.8.6 or 25.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2025-2866/");
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

if(version_is_less(version:version, test_version:"24.8.6")) {
  fix = "24.8.6";
}

if(version_in_range_exclusive(version:version, test_version_lo:"25.0", test_version_up:"25.2.2")) {
  fix = "25.2.2";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
