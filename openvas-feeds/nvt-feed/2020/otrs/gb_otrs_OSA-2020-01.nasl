# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143345");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2020-01-13 04:44:37 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-23 15:15:00 +0000 (Wed, 23 Sep 2020)");

  script_cve_id("CVE-2020-1765", "CVE-2020-1766");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 5.0.x < 5.0.40, 6.0.x < 6.0.25, 7.0.x < 7.0.14 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"OTRS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-1765: Spoofing of From field in several screens

  - CVE-2020-1766: Improper handling of uploaded inline images");

  script_tag(name:"affected", value:"OTRS versions 5.0.x through 5.0.39, 6.0.x through 6.0.24 and
  7.0.x through 7.0.13.");

  script_tag(name:"solution", value:"Update to version 5.0.40, 6.0.25, 7.0.14 or later.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2020-01/");
  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2020-02/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.40", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
