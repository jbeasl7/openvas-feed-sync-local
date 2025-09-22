# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114889");
  script_version("2024-12-24T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-12-24 05:05:31 +0000 (Tue, 24 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-18 10:51:50 +0000 (Wed, 18 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-50379", "CVE-2024-54677", "CVE-2024-56337");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Multiple Vulnerabilities (Dec 2024) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-50379: Remote code execution (RCE) via write-enabled default servlet

  - CVE-2024-54677: Denial of service (DoS) in examples web application

  - CVE-2024-56337: RCE via write-enabled default servlet - CVE-2024-50379 mitigation was
  incomplete");

  script_tag(name:"affected", value:"Apache Tomcat versions prior to 9.0.98, 10.x prior to 10.1.34
  and 11.x prior to 11.0.2.

  Note: While not explicitly mentioned by the vendor (due to the EOL status of these branches) it is
  assumed that the whole 10.x branch and all versions prior to 9.x are affected by these flaws. If
  you disagree with this assessment and want to accept the risk please create an override for this
  result.");

  script_tag(name:"solution", value:"Update to version 9.0.98, 10.1.34, 11.0.2 or later.

  Vendor note: Users running Tomcat on a case insensitive file system with the default servlet write
  enabled (readonly initialisation parameter set to the non-default value of false) may need
  additional configuration to fully mitigate CVE-2024-50379 depending on which version of Java they
  are using with Tomcat:

  - running on Java 8 or Java 11: the system property sun.io.useCanonCaches must be explicitly set
  to false (it defaults to true)

  - running on Java 17: the system property sun.io.useCanonCaches, if set, must be set to false (it
  defaults to false)

  - running on Java 21 onwards: no further configuration is required (the system property and the
  problematic cache have been removed)");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/y6lj6q1xnp822g6ro70tn19sgtjmr80r");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/tdtbbxpg5trdwc2wnopcth9ccvdftq2n");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/b2b9qrgjrz1kvo4ym8y2wkfdvwoq6qbp");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.2");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.34");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.98");

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

if (version_is_less(version: version, test_version: "9.0.98")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.98", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.1.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
