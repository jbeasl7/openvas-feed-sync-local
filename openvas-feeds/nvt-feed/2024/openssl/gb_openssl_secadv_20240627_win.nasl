# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114676");
  script_version("2024-10-18T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-10-18 05:05:38 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-06-27 10:34:06 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2024-5535");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Buffer Overread Vulnerability (20240627) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a buffer overread vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Calling the OpenSSL API function SSL_select_next_proto with an
  empty supported client protocols buffer may cause a crash or memory contents to be sent to the
  peer.");

  script_tag(name:"impact", value:"A buffer overread can have a range of potential consequences such
  as unexpected application behaviour or a crash.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.2, 1.1.1, 3.0, 3.1, 3.2 and 3.3.");

  script_tag(name:"solution", value:"Update to version 1.0.2zk, 1.1.1za, 3.0.15, 3.1.7, 3.2.3, 3.3.2
  or later.");

  script_xref(name:"URL", value:"https://openssl-library.org/news/secadv/20240627.txt");
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

if (version_in_range_exclusive(version: version, test_version_lo: "1.0.2", test_version_up: "1.0.2zk")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2zk", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.1.1", test_version_up: "1.1.1za")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1za", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.0", test_version_up: "3.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.1", test_version_up: "3.1.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.2", test_version_up: "3.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.3", test_version_up: "3.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
