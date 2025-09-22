# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104655");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-23 14:57:39 +0000 (Thu, 23 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-29 19:37:00 +0000 (Wed, 29 Mar 2023)");

  script_cve_id("CVE-2023-0464", "CVE-2023-0465", "CVE-2023-0466", "CVE-2023-2650");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Multiple Vulnerabilities (20230322, 20230328, 20230530) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-0464: Excessive Resource Usage Verifying X.509 Policy Constraints

  - CVE-2023-0465: Invalid certificate policies in leaf certificates are silently ignored

  - CVE-2023-0466: Certificate policy check not enabled

  - CVE-2023-2650: Possible DoS translating ASN.1 object identifiers");

  script_tag(name:"affected", value:"OpenSSL version 1.0.2, 1.1.1, 3.0 and 3.1.");

  script_tag(name:"solution", value:"Update to version 1.0.2zh, 1.1.1u, 3.0.9, 3.1.1 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230322.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230328.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230530.txt");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.0.2", test_version_up: "1.0.2zh")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2zh", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.1.1", test_version_up: "1.1.1u")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1u", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.0.0", test_version_up: "3.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
