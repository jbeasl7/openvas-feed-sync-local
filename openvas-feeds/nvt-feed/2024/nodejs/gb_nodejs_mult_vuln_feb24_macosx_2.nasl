# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151750");
  script_version("2025-04-03T05:39:15+0000");
  script_tag(name:"last_modification", value:"2025-04-03 05:39:15 +0000 (Thu, 03 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-02-16 05:30:15 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-02 20:09:59 +0000 (Wed, 02 Apr 2025)");

  script_cve_id("CVE-2024-21892", "CVE-2024-22019", "CVE-2024-21896", "CVE-2024-22017",
                "CVE-2023-46809", "CVE-2024-21891", "CVE-2024-21890", "CVE-2024-22025",
                "CVE-2024-24806", "CVE-2024-24758", "CVE-2023-5678", "CVE-2023-6129",
                "CVE-2023-6237", "CVE-2024-0727");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 20.x < 20.11.1, 21.x < 21.6.2 Multiple Vulnerabilities - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-5678, CVE-2023-6129, CVE-2023-6237, CVE-2024-0727: Multiple vulnerabilities in OpenSSL

  - CVE-2024-21892: Code injection and privilege escalation through Linux capabilities

  - CVE-2024-22019: Reading unprocessed HTTP request with unbounded chunk extension allows DoS
  attacks

  - CVE-2024-21896: Path traversal by monkey-patching Buffer internals

  - CVE-2024-22017: setuid() does not drop all privileges due to io_uring

  - CVE-2023-46809: Node.js is vulnerable to the Marvin Attack (timing variant of the
  Bleichenbacher attack against PKCS#1 v1.5 padding)

  - CVE-2024-21891: Multiple permission model bypasses due to improper path traversal sequence
  sanitization

  - CVE-2024-21890: Improper handling of wildcards in --allow-fs-read and --allow-fs-write

  - CVE-2024-22025: Denial of Service by resource exhaustion in fetch() brotli decoding

  - CVE-2024-24758: Vulnerability in undici

  - CVE-2024-24806: Vulnerability in libuv");

  script_tag(name:"affected", value:"Node.js version 20.x, 21.x.");

  script_tag(name:"solution", value:"Update to version 20.11.1, 21.6.2 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/february-2024-security-releases");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/main/doc/changelogs/CHANGELOG_V20.md#20.11.1");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/main/doc/changelogs/CHANGELOG_V21.md#21.6.2");
  script_xref(name:"URL", value:"https://github.com/nodejs/undici/security/advisories/GHSA-3787-6prv-h9w3");
  script_xref(name:"URL", value:"https://mta.openssl.org/pipermail/openssl-announce/2023-November/000284.html");
  script_xref(name:"URL", value:"https://mta.openssl.org/pipermail/openssl-announce/2024-January/000288.html");
  script_xref(name:"URL", value:"https://mta.openssl.org/pipermail/openssl-announce/2024-January/000289.html");
  script_xref(name:"URL", value:"https://mta.openssl.org/pipermail/openssl-announce/2024-January/000292.html");

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

if (version_in_range_exclusive(version: version, test_version_lo: "20.0", test_version_up: "20.11.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.11.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "21.0", test_version_up: "21.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.6.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
