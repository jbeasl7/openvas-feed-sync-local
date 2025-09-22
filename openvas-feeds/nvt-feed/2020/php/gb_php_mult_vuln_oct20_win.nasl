# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144695");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-10-02 04:25:30 +0000 (Fri, 02 Oct 2020)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_cve_id("CVE-2020-7069", "CVE-2020-7070");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 7.2.34, 7.3 < 7.3.23, 7.4 < 7.4.11 Multiple Vulnerabilities (Oct 2020) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Wrong ciphertext/tag in AES-CCM encryption for a 12 bytes IV (CVE-2020-7069)

  - PHP parses encoded cookie names so malicious '__Host-' cookies can be sent (CVE-2020-7070)");

  script_tag(name:"affected", value:"PHP versions prior 7.2.34, 7.3 prior 7.3.23 and 7.4 prior to 7.4.11.");

  script_tag(name:"solution", value:"Update to version 7.2.34, 7.3.23, 7.4.11 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.2.34");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.3.23");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.4.11");

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

if (version_is_less(version: version, test_version: "7.2.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);

}

if (version_in_range(version: version, test_version: "7.3.0", test_version2: "7.3.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.4.0", test_version2: "7.4.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
