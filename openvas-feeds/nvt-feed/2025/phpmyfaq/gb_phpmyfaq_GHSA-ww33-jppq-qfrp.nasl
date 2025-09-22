# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131382");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-01-03 09:08:56 +0200 (Fri, 03 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-14 17:54:26 +0000 (Thu, 14 Aug 2025)");

  script_cve_id("CVE-2024-56199");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ 3.2.10 < 4.0.2 HTML Injection Vulnerability (GHSA-ww33-jppq-qfrp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyfaq_http_detect.nasl");
  script_mandatory_keys("phpmyfaq/detected");

  script_tag(name:"summary", value:"phpMyFAQ is prone to an HTML injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to insufficient validation on the content of new FAQ
  posts, it is possible for authenticated users to inject malicious HTML or JavaScript code that can
  impact other users viewing the FAQ. This arises when user-provided inputs in FAQ entries are not
  sanitized or escaped before being rendered on the page.");

  script_tag(name:"affected", value:"phpMyFAQ version 3.2.10 prior to 4.0.2.");

  script_tag(name:"solution", value:"Update to version 4.0.2 or later.");

  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-ww33-jppq-qfrp");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.2.10", test_version_up: "4.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
