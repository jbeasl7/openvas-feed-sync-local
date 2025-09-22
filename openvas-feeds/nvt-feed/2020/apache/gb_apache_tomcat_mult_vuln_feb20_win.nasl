# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143550");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-02-25 03:22:23 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-24 12:15:00 +0000 (Wed, 24 Feb 2021)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-1935", "CVE-2020-1938");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Multiple Vulnerabilities (Feb 2020) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Apache Tomcat is prone to multiple vulnerabilities:

  - HTTP request smuggling vulnerability (CVE-2020-1935)

  - AJP Request Injection and potential Remote Code Execution dubbed 'Ghostcat' (CVE-2020-1938)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat 7.0.0 to 7.0.99, 8.5.0 to 8.5.50 and 9.0.0.M1 to 9.0.30.");

  script_tag(name:"solution", value:"Update to version 7.0.100, 8.5.51, 9.0.31 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r127f76181aceffea2bd4711b03c595d0f115f63e020348fe925a916c%40%3Cannounce.tomcat.apache.org%3E");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r7c6f492fbd39af34a68681dbbba0468490ff1a97a1bd79c6a53610ef%40%3Cannounce.tomcat.apache.org%3E");
  script_xref(name:"URL", value:"https://www.chaitin.cn/en/ghostcat");
  script_xref(name:"URL", value:"https://www.cnvd.org.cn/flaw/show/CNVD-2020-10487");
  script_xref(name:"URL", value:"https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi");
  script_xref(name:"URL", value:"https://tomcat.apache.org/tomcat-7.0-doc/changelog.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/tomcat-8.5-doc/changelog.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/tomcat-9.0-doc/changelog.html");

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

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.0.99")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.100", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.51", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0.M1") >= 0) && (revcomp(a: version, b: "9.0.30") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
