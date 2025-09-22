# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141569");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-10-05 11:08:04 +0700 (Fri, 05 Oct 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-11 22:29:00 +0000 (Tue, 11 Jun 2019)");

  script_cve_id("CVE-2018-11784");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Open Redirect Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"When the default servlet in Apache Tomcat returned a redirect to a directory
(e.g. redirecting to '/foo/' when the user requested '/foo') a specially crafted URL could be used to cause the
redirect to be generated to any URI of the attackers choice.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat 9.0.0.M1-9.0.11, 8.5.0-8.5.33, 7.0.23-7.0.90 and probably
8.0.x.");

  script_tag(name:"solution", value:"Update to version 7.0.91, 8.5.34, 9.0.12 or later.");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");

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
path = infos["location"];

if (version_in_range(version: version, test_version: "7.0.23", test_version2: "7.0.90")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.91", install_path:path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.5.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.34", install_path:path);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0.M1") >= 0) && (revcomp(a: version, b: "9.0.12") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.12", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
