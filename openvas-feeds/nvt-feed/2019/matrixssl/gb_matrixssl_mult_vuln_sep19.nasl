# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:matrixssl:matrixssl";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.142693");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-08-05 07:31:52 +0000 (Mon, 05 Aug 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 02:46:00 +0000 (Fri, 03 Mar 2023)");

  script_cve_id("CVE-2019-13629", "CVE-2019-14431", "CVE-2019-16747");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MatrixSSL < 4.2.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_matrixssl_http_detect.nasl");
  script_mandatory_keys("matrixssl/detected");

  script_tag(name:"summary", value:"MatrixSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-13629: MatrixSSL contains a timing side channel in ECDSA signature generation. This
  allows a local or a remote attacker to measure the duration of hundreds to thousands of signing
  operations, to compute the private key used. The issue occurs because crypto/pubkey/ecc_math.c
  scalar multiplication leaks the bit length of the scalar.

  - CVE-2019-14431: The DTLS server mishandles incoming network messages leading to a heap-based
  buffer overflow of up to 256 bytes and possible Remote Code Execution in parseSSLHandshake in
  sslDecode.c. During processing of a crafted packet, the server mishandles the fragment length
  value provided in the DTLS message.

  - CVE-2019-16747: Memory corruption (free on invalid pointer) while parsing DTLS messages");

  script_tag(name:"affected", value:"MatrixSSL version 4.2.1 and prior.");

  script_tag(name:"solution", value:"Update to version 4.2.2 or later.");

  script_xref(name:"URL", value:"https://github.com/matrixssl/matrixssl/blob/4-2-2-open/doc/CHANGES_v4.x.md");
  script_xref(name:"URL", value:"https://github.com/matrixssl/matrixssl/releases/tag/4-2-2-open");
  script_xref(name:"URL", value:"https://github.com/matrixssl/matrixssl/issues/33");
  script_xref(name:"URL", value:"https://github.com/matrixssl/matrixssl/issues/30");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/10/02/2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
