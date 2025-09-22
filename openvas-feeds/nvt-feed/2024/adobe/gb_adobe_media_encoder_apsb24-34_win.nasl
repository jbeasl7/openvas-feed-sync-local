# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:media_encoder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834058");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2024-30278");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-13 10:15:09 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-13 13:03:48 +0530 (Thu, 13 Jun 2024)");
  script_name("Adobe Media Encoder Memory Leak Vulnerability (APSB24-34) - Windows");

  script_tag(name:"summary", value:"Adobe Media Encoder is prone to a memory
  leak vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds
  read error.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to disclose sensitive information.");

  script_tag(name:"affected", value:"Adobe Media Encoder 23.6.5 and prior and 24.x
  through 24.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 23.6.6 or 24.4.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/media-encoder/apsb24-23.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_media_encoder_detect_win.nasl");
  script_mandatory_keys("adobe/mediaencoder/win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_less(version: vers, test_version: "23.6.6")) {
  fix = "23.6.6";
}

if (version_in_range(version: vers, test_version: "24.0", test_version2: "24.3")) {
  fix = "24.4.1";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
