# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:splunk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106541");
  script_version("2024-01-25T14:38:15+0000");
  script_tag(name:"last_modification", value:"2024-01-25 14:38:15 +0000 (Thu, 25 Jan 2024)");
  script_tag(name:"creation_date", value:"2017-01-24 10:40:31 +0700 (Tue, 24 Jan 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-18 02:59:00 +0000 (Wed, 18 Jan 2017)");

  script_cve_id("CVE-2016-10126");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Enterprise HTTP Request Injection Vulnerability (SP-CAAAPSR)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_http_detect.nasl");
  script_mandatory_keys("splunk/detected");

  script_tag(name:"summary", value:"Splunk Enterprise is prone to a HTTP request injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Splunk Web in Splunk Enterprise allows remote attackers to
  conduct HTTP request injection attacks and obtain sensitive REST API authentication-token
  information via unspecified vectors.");

  script_tag(name:"affected", value:"Splunk Enterprise 5.0.x, 6.0.x, 6.1.x, 6.2.x, 6.3.x and 6.4.x.");

  script_tag(name:"solution", value:"Update to version 5.0.17, 6.0.13, 6.1.12, 6.2.12, 6.3.8, 6.4.4
  or later.");

  script_xref(name:"URL", value:"https://www.splunk.com/view/SP-CAAAPSR");

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
  if (version_is_less(version: version, test_version: "5.0.17")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.0.17", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.0") {
  if (version_is_less(version: version, test_version: "6.0.13")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.0.13", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.1") {
  if (version_is_less(version: version, test_version: "6.1.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.1.12", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.2") {
  if (version_is_less(version: version, test_version: "6.2.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.2.12", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.3") {
  if (version_is_less(version: version, test_version: "6.3.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.3.8", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.4") {
  if (version_is_less(version: version, test_version: "6.4.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.4.4", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
