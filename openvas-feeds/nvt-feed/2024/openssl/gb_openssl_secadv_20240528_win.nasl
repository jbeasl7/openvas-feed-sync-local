# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114641");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-05-29 07:28:06 +0000 (Wed, 29 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2024-4741");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL UAF Vulnerability (20240528) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a use after free (UAF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Calling the OpenSSL API function SSL_free_buffers may cause
  memory to be accessed that was previously freed in some situations.");

  script_tag(name:"impact", value:"A use after free can have a range of potential consequences such
  as the corruption of valid data, crashes or execution of arbitrary code.");

  script_tag(name:"affected", value:"OpenSSL versions 1.1.1, 3.0, 3.1, 3.2 and 3.3.");

  script_tag(name:"solution", value:"Update to version 1.1.1y, 3.0.14, 3.1.6, 3.2.2, 3.3.1 or
  later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20240528.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/vulnerabilities.html");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.0", test_version_up: "3.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.1", test_version_up: "3.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.2", test_version_up: "3.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.3", test_version_up: "3.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
