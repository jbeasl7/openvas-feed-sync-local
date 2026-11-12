# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119542");
  script_version("2026-11-11T05:38:42+0000");
  script_tag(name:"last_modification", value:"2026-11-11 05:38:42 +0000 (Wed, 11 Nov 2026)");
  script_tag(name:"creation_date", value:"2026-10-21 06:08:34 +0000 (Wed, 21 Oct 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-10-21 17:01:03 +0000 (Wed, 21 Oct 2026)");

  script_cve_id("CVE-2026-109618", "CVE-2026-109619", "CVE-2026-111497");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Multiple Vulnerabilities (Oct 2026, PHP2Shell) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2026-109618 / GHSA-w8hw-w9fx-j79w: Remote code execution (RCE) via OOM corruption.
  out-of-memory handling can interrupt PHP while internal request data is only partially
  initialized. Request cleanup may then treat the invalid data as valid.

  - CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp: RCE via stale global state. request-owned internal state
  can survive after its backing memory has been freed. A later request handled by the same worker
  may use that stale state before normal initialization resets it.

  - CVE-2026-111497: A buffer overflow vulnerability in the Brotli decoder (c/dec/decode.c) in
  Google Brotli. In PHP Windows builds, the vulnerable decoder can be reached through the cURL
  extension when automatic HTTP response decompression is enabled. This is disabled by default in
  cURL, but applications and HTTP client libraries can enable it.

  The RCE vulnerabilities in PHP are collectively dubbed 'PHP2Shell'.");

  # nb: External resources are indicating e.g. the following affected ranges:
  # - The specific HashTable ordering behind CVE-2026-109618 was introduced by a performance
  #   optimization in October 2017 and first shipped in PHP 7.3.0 (December 2018).
  # - The serialization and session paths behind CVE-2026-109619 date back further, to PHP 7.1 and
  #   PHP 5.4, respectively.
  # For now we are using < 8.2.35 until officially confirmed / there is reliable info about this.
  script_tag(name:"affected", value:"PHP prior to version 8.2.35, 8.3.x prior to 8.3.36, 8.4.x
  prior to 8.4.27 and 8.5.x prior to 8.5.12.");

  # nb: From the advisory about the Brotli rebuild:
  #
  # > The -1 suffix identifies a Windows package rebuild with updated dependencies. These builds use
  # > the same PHP source releases, and the PHP runtime versions remain unchanged.
  #
  # An analysis has shown that there is no indicator for this / to detect this package rebuild:
  # php.exe is the same hash and the Brotli files have no file version or similar. For now we have
  # added the Brotli CVE to this VT here as we (at least currently) can't handle it via other means.
  script_tag(name:"solution", value:"Update to version 8.2.35, 8.3.36, 8.4.27, 8.5.12 or later.

  Note: When updating PHP please make sure to use / update to the rebuild Windows packages including
  the -1 suffix which got released on 26.10.2026.");

  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp");
  script_xref(name:"URL", value:"https://www.php.net/archive/2026.php#2026-10-21-5");
  script_xref(name:"URL", value:"https://www.php.net/archive/2026.php#2026-10-20-1");
  script_xref(name:"URL", value:"https://www.php.net/archive/2026.php#2026-10-21-4");
  script_xref(name:"URL", value:"https://www.php.net/archive/2026.php#2026-10-21-3");
  script_xref(name:"URL", value:"https://www.php.net/archive/2026.php#2026-10-21-1");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.35");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.3.36");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.4.27");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.5.12");
  script_xref(name:"URL", value:"https://www.php2shell.com/");
  script_xref(name:"URL", value:"https://calif.io/php2shell/#php-5-4-0-rce");
  script_xref(name:"URL", value:"https://watchtowr.com/intelligence/php-cve-2026-109618-faq/");
  script_xref(name:"URL", value:"https://cert.europa.eu/publications/security-advisories/2026-018/");
  script_xref(name:"URL", value:"https://www.cyberkendra.com/2026/10/php-cve-2026-109618-cve-2026-109619-rce.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/10/20/34");
  script_xref(name:"URL", value:"https://github.com/NCSC-NL/php2shell");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching");
  script_xref(name:"URL", value:"https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2026/Oct/38");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/763488");
  script_xref(name:"URL", value:"https://www.php.net/archive/2026.php#2026-10-26-1");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-9v8h-qqgm-4m35");
  script_xref(name:"URL", value:"https://broccoli2shell.com/");
  script_xref(name:"URL", value:"https://www.aikido.dev/blog/node2shell-nodejs-brotli-rce-cve-2026-111497");
  script_xref(name:"URL", value:"https://patchtheplanet.org/brotli");

  # nb: Those two are currently claiming a wrong "8.2-8.5" affected range. The vendor info clearly
  # shows that the PHP security team provided minimal source-backports for PHP 7.4, PHP 8.0, and
  # PHP 8.1.
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/10/21/7");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/10/21/6");

  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

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

if (version_is_less(version: version, test_version: "8.2.35")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.35", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.3", test_version_up: "8.3.36")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.3.36", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.4", test_version_up: "8.4.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
