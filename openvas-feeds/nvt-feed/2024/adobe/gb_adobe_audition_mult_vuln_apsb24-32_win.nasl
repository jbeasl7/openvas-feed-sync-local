# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:audition";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834057");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2024-30276", "CVE-2024-30285");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-13 09:15:10 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-13 12:19:29 +0530 (Thu, 13 Jun 2024)");
  script_name("Adobe Audition Multiple Vulnerabilities (APSB24-32) - Windows");

  script_tag(name:"summary", value:"Adobe Audition is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-30276: Out-of-bounds Read

  - CVE-2024-30285: NULL Pointer Dereference

  Please see the references for more information on the vulnerabilities.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to run arbitrary code, conduct spoofing and cause  denial of service
  attacks.");

  script_tag(name:"affected", value:"Adobe Audition 24.2 and prior, 23.x
  through 23.6.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 24.4.1 or 23.6.6 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/audition/apsb24-32.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Audition/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range_exclusive(version:vers, test_version_lo:"23.0", test_version_up:"23.6.6")) {
  fix = "23.6.6 or later";
}

if(version_in_range_exclusive(version:vers, test_version_lo:"24.0", test_version_up:"24.4.1")) {
  fix = "24.4.1 or later";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
