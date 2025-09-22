# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144180");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-06-29 08:59:09 +0000 (Mon, 29 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-12 12:53:00 +0000 (Fri, 12 Mar 2021)");

  script_cve_id("CVE-2020-11996");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat DoS Vulnerability (Jun 2020) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"A specially crafted sequence of HTTP/2 requests sent to Apache Tomcat could
  trigger high CPU usage for several seconds. If a sufficient number of such requests were made on concurrent
  HTTP/2 connections, the server could become unresponsive.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat 8.5.0 to 8.5.55, 9.0.0.M1 to 9.0.35 and
  10.0.0-M1 to 10.0.0-M5.");

  script_tag(name:"solution", value:"Update to version 8.5.56, 9.0.36, 10.0.0-M6 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r5541ef6b6b68b49f76fc4c45695940116da2bcbe0312ef204a00a2e0%40%3Cannounce.tomcat.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.55")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.56", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0.M1") >= 0) && (revcomp(a: version, b: "9.0.35") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.36", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "10.0.0.M1") >= 0) && (revcomp(a: version, b: "10.0.0.M5") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.0-M6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
