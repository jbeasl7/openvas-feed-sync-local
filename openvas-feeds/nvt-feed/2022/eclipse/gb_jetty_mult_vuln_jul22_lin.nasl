# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148412");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2022-07-08 02:49:20 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 15:35:00 +0000 (Fri, 15 Jul 2022)");

  script_cve_id("CVE-2022-2047", "CVE-2022-2048");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Multiple Vulnerabilities (Jul 2022) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-2047: Invalid URI parsing may produce invalid HttpURI.authority

  - CVE-2022-2048: Invalid HTTP/2 requests can lead to denial of service");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.4.46 and prior, version 10.0.x through
  10.0.9 and 11.0.x through 11.0.9.");

  script_tag(name:"solution", value:"Update to version 9.4.47, 10.0.10, 11.0.10 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-cj7v-27pg-wf7q");
  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-wgmr-mf83-7x4j");

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

if (version_is_less(version: version, test_version: "9.4.47")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.47", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
