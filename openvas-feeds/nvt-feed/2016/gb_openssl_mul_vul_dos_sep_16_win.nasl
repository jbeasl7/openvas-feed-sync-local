# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107049");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2016-6306", "CVE-2016-6303", "CVE-2016-2181", "CVE-2016-6302", "CVE-2016-2182",
                "CVE-2016-2180", "CVE-2016-2179");

  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"creation_date", value:"2016-09-26 06:40:16 +0200 (Mon, 26 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:17:00 +0000 (Tue, 16 Aug 2022)");

  script_name("OpenSSL 1.0.2 and 1.0.1 Multiple Vulnerabilities (Sep 2016) - Windows");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160922.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"OpenSSL suffers from the possibility of multiple vulnerabilities due to:

  1) Missing message length checks which results in Out of Bounds reads up to 2 bytes beyond the allocated buffer, this leads to Denial of Service.
  The attack works only if client authentication is enabled.

  2) Calling MDC2_Update() can cause an overflow if an attacker is able to supply very large amounts of input data after a previous
  call to EVP_EncryptUpdate() with a partial block then a length check can overflow resulting in a heap corruption.

  3) A malfored SHA512 TLS session ticket resulting in an Out of Bounds read which leads to service crash.

  4) Unchecking the return value of BN_div_word() function causing an Out of Bounds write if it is used with an overly large BIGNUM. TLS is not affected.

  5) Misusing OBJ_obj2txt() function by the function TS_OBJ_print_bio() will results in Out of Bounds reads when large OIDs are presented.

  6) DTLS out-of-order messages handling which enable an attacker to cause a DoS attack through memory exhaustion.

  7) A flaw in the DTLS replay attack protection mechanism enabling the attacker to send records for next epochs with a very large sequence number,
  this causes in dropping all the subsequent legitimate packets and causing a denial of service for a specific DTLS connection.");

  script_tag(name:"impact", value:"Successful exploitation could result in Denial of Service.");

  script_tag(name:"affected", value:"OpenSSL 1.0.2 and 1.0.1.");

  script_tag(name:"solution", value:"OpenSSL 1.0.2 users should upgrade to 1.0.2i, OpenSSL 1.0.1 users should upgrade to 1.0.1u.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.0\.2" && version_is_less(version:vers, test_version:"1.0.2i")) {
  fix = "1.0.2i";
  VUL = TRUE;
}
else if(vers =~ "^1\.0\.1" && version_is_less(version:vers, test_version:"1.0.1u")) {
  fix = "1.0.1u";
  VUL = TRUE;
}

if(VUL) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
