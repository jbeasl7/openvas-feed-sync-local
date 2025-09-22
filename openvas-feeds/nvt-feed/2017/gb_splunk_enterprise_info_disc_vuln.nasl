# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:splunk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106715");
  script_version("2024-01-25T14:38:15+0000");
  script_cve_id("CVE-2017-5607");
  script_tag(name:"last_modification", value:"2024-01-25 14:38:15 +0000 (Thu, 25 Jan 2024)");
  script_tag(name:"creation_date", value:"2017-04-03 09:45:47 +0700 (Mon, 03 Apr 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-20 19:23:00 +0000 (Wed, 20 Mar 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Enterprise Information Disclosure Vulnerability (SP-CAAAPZ3)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_http_detect.nasl");
  script_mandatory_keys("splunk/detected");

  script_tag(name:"summary", value:"Splunk Enterprise is prone to an information disclosure
  vulnerability via JavaScript.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Splunk Enterprise is affected by a vulnerability that could
  allow a remote attacker to obtain logged-in username and Splunk version-related information via
  JavaScript.");

  script_tag(name:"affected", value:"Splunk Enterprise 5.0.x, 6.0.x, 6.1.x, 6.2.x, 6.3.x, 6.4.x and
  6.5.x.");

  script_tag(name:"solution", value:"Update to version 5.0.18, 6.0.14, 6.1.13, 6.2.13, 6.3.10,
  6.4.6, 6.5.3 or later.");

  script_xref(name:"URL", value:"https://www.splunk.com/view/SP-CAAAPZ3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^5\.0") {
  if (version_is_less(version: version, test_version: "5.0.18")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.0.18", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.0") {
  if (version_is_less(version: version, test_version: "6.0.14")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.0.14", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.1") {
  if (version_is_less(version: version, test_version: "6.1.13")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.1.13", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.2") {
  if (version_is_less(version: version, test_version: "6.2.13")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.2.13", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.3") {
  if (version_is_less(version: version, test_version: "6.3.10")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.3.10", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.4") {
  if (version_is_less(version: version, test_version: "6.4.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.4.6", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.5") {
  if (version_is_less(version: version, test_version: "6.5.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.5.3", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
