# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:facebook:hhvm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142671");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-07-29 05:01:14 +0000 (Mon, 29 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-16 15:14:00 +0000 (Fri, 16 Oct 2020)");

  script_cve_id("CVE-2019-3569", "CVE-2019-3570");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HHVM Multiple Vulnerabilities (Jun 2019)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hhvm_detect.nasl");
  script_mandatory_keys("HHVM/detected");

  script_tag(name:"summary", value:"HHMV is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"HHMV is prone to multiple vulnerabilities:

  - Vulnerability in FastCGI interface (CVE-2019-3569)

  - Heap corruption in scrypt_enc() (CVE-2019-3570)");

  script_tag(name:"solution", value:"Update to version 3.30.6, 4.3.1, 4.4.1, 4.5.1, 4.6.1, 4.7.1, 4.8.1 or later.");

  script_xref(name:"URL", value:"https://hhvm.com/blog/2019/06/10/hhvm-4.9.0.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "3.30.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.30.6", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.8.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
