# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152058");
  script_version("2024-04-10T05:05:22+0000");
  script_tag(name:"last_modification", value:"2024-04-10 05:05:22 +0000 (Wed, 10 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-09 02:49:47 +0000 (Tue, 09 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2024-2511");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL DoS Vulnerability (20240408) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Some non-default TLS server configurations can cause unbounded
  memory growth when processing TLSv1.3 sessions.");

  script_tag(name:"impact", value:"An attacker may exploit certain server configurations to trigger
  unbounded memory growth that would lead to a Denial of Service.");

  script_tag(name:"affected", value:"OpenSSL versions 1.1.1, 3.0, 3.1 and 3.2.");

  script_tag(name:"solution", value:"Update to version 1.1.1y, 3.0.14, 3.1.6, 3.2.2 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20240408.txt");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.1.1", test_version_up: "1.1.1y")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1y", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.0.0", test_version_up: "3.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.1.0", test_version_up: "3.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.2.0", test_version_up: "3.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
