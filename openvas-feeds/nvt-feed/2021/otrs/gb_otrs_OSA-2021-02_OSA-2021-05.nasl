# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145344");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2021-02-10 06:06:13 +0000 (Wed, 10 Feb 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-09 20:33:00 +0000 (Tue, 09 Feb 2021)");

  script_cve_id("CVE-2018-17960", "CVE-2021-21435");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 6.0.x < 7.0.24, 8.0.x < 8.0.11 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"OTRS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2018-17960: OTRS is shipping a 3rdparty CKEditor component which has several security issues
  e.g. XSS and ReDoS.

  - CVE-2021-21435: Article Bcc fields and agent personal information are shown when a customer
  prints the ticket (PDF) via an external interface.");

  script_tag(name:"affected", value:"OTRS versions 6.x, 7.x prior to 7.0.24 and 8.0.x prior to
  8.0.11.");

  script_tag(name:"solution", value:"Update to version 7.0.24, 8.0.11 or later.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2021-02/");
  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2021-05/");

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

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "7.0.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
