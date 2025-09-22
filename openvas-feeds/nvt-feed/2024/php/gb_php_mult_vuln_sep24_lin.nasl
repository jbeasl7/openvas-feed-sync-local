# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114787");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-09-27 09:52:39 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-16 18:35:59 +0000 (Wed, 16 Oct 2024)");

  script_cve_id("CVE-2024-8925", "CVE-2024-8926", "CVE-2024-8927", "CVE-2024-8928",
                "CVE-2024-9026");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 8.1.30, 8.2.x < 8.2.24, 8.3.x < 8.3.12 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_php_ssh_login_detect.nasl",
                      "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-8925, CVE-2024-8928: Erroneous parsing of multipart form data

  - CVE-2024-8926: Bypass of CVE-2024-4577, Parameter Injection Vulnerability

  - CVE-2024-8927: cgi.force_redirect configuration is bypassable due to the environment variable
  collision

  - CVE-2024-9026: Logs from children may be altered");

  script_tag(name:"affected", value:"PHP versions prior to 8.1.30, 8.2.x prior to 8.2.24 and 8.3.x
  prior to 8.3.12.");

  script_tag(name:"solution", value:"Update to version 8.1.30, 8.2.24, 8.3.12 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.30");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.24");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.3.12");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-9pqp-7h25-4f32");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-p99j-rfp4-xqvq");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-94p6-54jq-9mwp");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-865w-9rf3-2wh5");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317439");
  script_xref(name:"URL", value:"https://thephp.foundation/blog/2025/04/10/php-core-security-audit-results/");
  script_xref(name:"URL", value:"https://ostif.org/php-audit-complete/");
  script_xref(name:"URL", value:"https://blog.quarkslab.com/security-audit-of-php-src.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/04/12/2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "8.1.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.2", test_version_up: "8.2.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.3", test_version_up: "8.3.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
