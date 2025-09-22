# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154000");
  script_version("2025-02-14T08:35:38+0000");
  script_tag(name:"last_modification", value:"2025-02-14 08:35:38 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-12 05:13:40 +0000 (Wed, 12 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2024-12797");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL RPKs Vulnerability (20250211) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a vulnerability in the RFC7250 Raw Public
  Keys (RPKs) handshake.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Clients using RFC7250 Raw Public Keys (RPKs) to authenticate a
  server may fail to notice that the server was not authenticated, because handshakes don't abort
  as expected when the SSL_VERIFY_PEER verification mode is set.");

  script_tag(name:"impact", value:"TLS and DTLS connections using raw public keys may be vulnerable
  to man-in-middle attacks when server authentication failure is not detected by clients.

  RPKs are disabled by default in both TLS clients and TLS servers. The issue only arises when TLS
  clients explicitly enable RPK use by the server, and the server, likewise, enables sending of an
  RPK instead of an X.509 certificate chain. The affected clients are those that then rely on the
  handshake to fail when the server's RPK fails to match one of the expected public keys, by
  setting the verification mode to SSL_VERIFY_PEER.

  Clients that enable server-side raw public keys can still find out that raw public key
  verification failed by calling SSL_get_verify_result(), and those that do, and take appropriate
  action, are not affected.");

  script_tag(name:"affected", value:"OpenSSL versions 3.2, 3.3 and 3.4.");

  script_tag(name:"solution", value:"Update to version 3.2.4, 3.3.3, 3.4.1 or later.");

  script_xref(name:"URL", value:"https://openssl-library.org/news/secadv/20250211.txt");
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
