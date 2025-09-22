# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114829");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-10-17 06:19:40 +0000 (Thu, 17 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2024-9143");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL OOB Memory Access Vulnerability (20241016) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to an out of bound (OOB) memory access
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Use of the low-level GF(2^m) elliptic curve APIs with untrusted
  explicit values for the field polynomial can lead to out-of-bounds memory reads or writes.");

  script_tag(name:"impact", value:"Out of bound memory writes can lead to an application crash or
  even a possibility of a remote code execution, however, in all the protocols involving Elliptic
  Curve Cryptography that we're aware of, either only 'named curves' are supported, or, if explicit
  curve parameters are supported, they specify an X9.62 encoding of binary (GF(2^m)) curves that
  can't represent problematic input values. Thus the likelihood of existence of a vulnerable
  application is low.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.2, 1.1.1, 3.0, 3.1, 3.2 and 3.3.");

  script_tag(name:"solution", value:"Update to version 1.0.2zl, 1.1.1zb, 3.0.16, 3.1.8, 3.2.4, 3.3.3
  or later once available.

  Note: As of 01/2025 these updates have not been released yet.");

  script_xref(name:"URL", value:"https://openssl-library.org/news/secadv/20241016.txt");
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

exit(99);
