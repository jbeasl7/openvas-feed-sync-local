# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fortinet:fortiweb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105209");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"creation_date", value:"2015-02-11 12:17:13 +0000 (Wed, 11 Feb 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-28 16:40:00 +0000 (Tue, 28 Jul 2020)");

  script_cve_id("CVE-2014-0195", "CVE-2014-0221", "CVE-2014-0224");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiWeb Multiple Vulnerabilities in OpenSSL (FG-IR-14-018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortiweb_consolidation.nasl");
  script_mandatory_keys("fortinet/fortiweb/detected");

  script_tag(name:"summary", value:"Fortinet FortiWeb is prone to multiple vulnerabilities in
  OpenSSL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"CVE-2014-0224 may allow an attacker with a privileged network
  position (man-in-the-middle) to decrypt SSL encrypted communications.

  CVE-2014-0221 may allow an attacker to crash a DTLS client with an invalid handshake.

  CVE-2014-0195 can result in a buffer overrun attack by sending invalid DTLS fragments to an
  OpenSSL DTLS client or server.

  CVE-2014-0198 and CVE-2010-5298 may allow an attacker to cause a denial of service under certain
  conditions, when SSL_MODE_RELEASE_BUFFERS is enabled.

  CVE-2014-3470 may allow an attacker to trigger a denial of service in SSL clients when anonymous
  ECDH ciphersuites are enabled. This issue does not affect Fortinet products.

  CVE-2014-0076 can be used to discover ECDSA nonces on multi-user systems by exploiting timing
  attacks in CPU L3 caches. This does not apply to Fortinet products.");

  script_tag(name:"affected", value:"Fortinet FortiWeb prior to version 5.3.1.");

  script_tag(name:"solution", value:"Update to version 5.3.1 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-14-018");
  script_xref(name:"Advisory-ID", value:"FG-IR-14-018");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "5.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
