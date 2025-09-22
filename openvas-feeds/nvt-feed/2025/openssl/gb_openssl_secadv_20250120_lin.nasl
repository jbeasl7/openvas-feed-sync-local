# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114924");
  script_version("2025-02-18T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-02-18 05:38:27 +0000 (Tue, 18 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-01-20 14:44:46 +0000 (Mon, 20 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-13176");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Timing Side-Channel Vulnerability (20250120) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a timing side-channel vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A timing side-channel which could potentially allow recovering
  the private key exists in the ECDSA signature computation.");

  script_tag(name:"impact", value:"A timing side-channel in ECDSA signature computations could allow
  recovering the private key by an attacker. However, measuring the timing would require either
  local access to the signing application or a very fast network connection with low latency.

  There is a timing signal of around 300 nanoseconds when the top word of the inverted ECDSA nonce
  value is zero. This can happen with significant probability only for some of the supported
  elliptic curves. In particular the NIST P-521 curve is affected. To be able to measure this leak,
  the attacker process must either be located in the same physical computer or must have a very fast
  network connection with low latency. For that reason the severity of this vulnerability is Low.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.2, 1.1.1, 3.0, 3.1, 3.2, 3.3 and 3.4.");

  script_tag(name:"solution", value:"Update to version 1.0.2zl, 1.1.1zb, 3.0.16, 3.1.8, 3.2.4,
  3.3.3, 3.4.1 or later.");

  script_xref(name:"URL", value:"https://openssl-library.org/news/secadv/20250120.txt");
  script_xref(name:"URL", value:"https://openssl-library.org/news/vulnerabilities/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.0.2", test_version_up: "1.0.2zl")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2zl", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.1.1", test_version_up: "1.1.1zb")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1zb", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.0", test_version_up: "3.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.1", test_version_up: "3.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.2", test_version_up: "3.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.3", test_version_up: "3.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.4", test_version_up: "3.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
