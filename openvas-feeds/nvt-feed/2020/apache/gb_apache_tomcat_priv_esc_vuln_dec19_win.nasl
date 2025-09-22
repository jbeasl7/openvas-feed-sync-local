# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143312");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-01-07 03:21:10 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-07 08:15:00 +0000 (Tue, 07 Jan 2020)");

  script_cve_id("CVE-2019-12418");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Privilege Escalation Vulnerability (Dec 2019) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a privilege escalation vulnerability.");

  script_tag(name:"insight", value:"When Tomcat is configured with the JMX Remote Lifecycle Listener, a local
  attacker without access to the Tomcat process or configuration files is able to manipulate the RMI registry to
  perform a man-in-the-middle attack to capture user names and passwords used to access the JMX interface. The
  attacker can then use these credentials to access the JMX interface and gain complete control over the Tomcat
  instance.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat 7.0.0 to 7.0.97, 8.5.0 to 8.5.47 and 9.0.0.M1 to 9.0.28.");

  script_tag(name:"solution", value:"Update to version 7.0.99, 8.5.49, 9.0.29 or later. As a mitigation disable
  Tomcat's JmxRemoteLifecycleListener and use the built-in remote JMX facilities provided by the JVM.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/43530b91506e2e0c11cfbe691173f5df8c48f51b98262426d7493b67%40%3Cannounce.tomcat.apache.org%3E");

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

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.0.97")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.99", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.47")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.49", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0.M1") >= 0) && (revcomp(a: version, b: "9.0.28") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
