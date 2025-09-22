# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144735");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-10-20 03:53:11 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_cve_id("CVE-2020-13943");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat HTTP/2 Vulnerability (Oct 2020) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to an information disclosure vulnerability in HTTP/2.");

  script_tag(name:"insight", value:"If an HTTP/2 client exceeded the agreed maximum number of concurrent streams
  for a connection (in violation of the HTTP/2 protocol), it is possible that a subsequent request made on that
  connection could contain HTTP headers - including HTTP/2 pseudo headers - from a previous request rather than
  the intended headers. This could lead to users seeing responses for unexpected resources.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat 8.5.1 to 8.5.57, 9.0.0.M5 to 9.0.37 and 10.0.0-M1 to 10.0.0-M7.");

  script_tag(name:"solution", value:"Update to version 8.5.58, 9.0.38, 10.0.0-M8 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r4a390027eb27e4550142fac6c8317cc684b157ae314d31514747f307%40%3Cannounce.tomcat.apache.org%3E");

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

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.57")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.58", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0.M5") >= 0) && (revcomp(a: version, b: "9.0.37") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "10.0.0.M1") >= 0) && (revcomp(a: version, b: "10.0.0.M7") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.0-M8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
