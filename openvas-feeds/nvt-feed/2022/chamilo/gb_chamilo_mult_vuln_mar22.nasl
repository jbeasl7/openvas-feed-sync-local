# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124043");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-03-23 16:47:25 +0000 (Wed, 23 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-29 13:10:00 +0000 (Tue, 29 Mar 2022)");

  script_cve_id("CVE-2021-38745", "CVE-2021-40662", "CVE-2022-27421");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Chamilo LMS <= 1.11.14 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-38745 / Issue #81: Zero-click code injection

  - CVE-2021-40662 / Issue #83: Remote code execution (RCE)

  - CVE-2022-27421 / Issue #85: Privilege escalation to Platform Admin

  - Multiple CSRF, XSS, path traversal, SQL injection, RCE, file upload, SSRF, command injection,
  LFI, information disclosure, privilege escalation vulnerabilities (issues 44 - 86)");

  script_tag(name:"affected", value:"Chamilo LMS version 1.11.14 and prior.");

  script_tag(name:"solution", value:"Update to version 1.11.16 or later.");

  # nb: To "find" the actual fixed version of the flaw the "short" commit ID needs to be looked up
  # at the following changelog:
  script_xref(name:"URL", value:"https://11.chamilo.org/documentation/changelog.html#1.11.16");

  # CVE-2022-27421 / Issue #85:
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/d2be86122e5bc9f86c7b05a350c49d27989bf099");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-85-2021-08-11-High-impact-Low-risk-Broken-Access-Control-leading-to-Vertical-Privilege-Escalation");

  # CVE-2021-40662 / Issue #83:
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/e757c63ac8d154ada4bd3c1ebc9628dc1105537f");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-83-2021-08-11-High-impact-Moderate-risk-Cross-Site-Request-Forgery-CSRF-leading-to-Remote-Code-Execution");

  # CVE-2021-38745 / Issue #81:
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/0aa0dab9624ed0211edf85f4b50deebc23123421");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-81-2021-07-26-High-impact-Low-risk-Zero-Code-RCE-in-admin");

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

if (version_is_less(version: version, test_version: "1.11.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
