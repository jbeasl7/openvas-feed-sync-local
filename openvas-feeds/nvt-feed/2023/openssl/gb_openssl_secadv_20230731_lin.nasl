# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150799");
  script_version("2023-10-26T05:07:17+0000");
  script_tag(name:"last_modification", value:"2023-10-26 05:07:17 +0000 (Thu, 26 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-01 07:37:48 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-08 19:04:00 +0000 (Tue, 08 Aug 2023)");

  script_cve_id("CVE-2023-3817");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL DoS Vulnerability (20230731) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Checking excessively long DH keys or parameters may be very slow.");

  script_tag(name:"impact", value:"Applications that use the functions DH_check(), DH_check_ex() or
  EVP_PKEY_param_check() to check a DH key or DH parameters may experience long delays. Where the
  key or parameters that are being checked have been obtained from an untrusted source this may
  lead to a Denial of Service.");

  script_tag(name:"affected", value:"OpenSSL version 1.0.2, 1.1.1, 3.0 and 3.1.");

  script_tag(name:"solution", value:"Update to version 1.0.2zi, 1.1.1v, 3.0.10, 3.1.2 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230731.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/vulnerabilities-1.0.2.html#CVE-2023-3817");
  script_xref(name:"URL", value:"https://www.openssl.org/news/vulnerabilities-1.1.1.html#CVE-2023-3817");
  script_xref(name:"URL", value:"https://www.openssl.org/news/vulnerabilities-3.0.html#CVE-2023-3817");
  script_xref(name:"URL", value:"https://www.openssl.org/news/vulnerabilities-3.1.html#CVE-2023-3817");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.0.2", test_version_up: "1.0.2zi")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2zi", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.1.1", test_version_up: "1.1.1v")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1v", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.0.0", test_version_up: "3.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.1.0", test_version_up: "3.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
