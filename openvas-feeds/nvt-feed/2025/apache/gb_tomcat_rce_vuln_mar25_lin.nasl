# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154160");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-03-11 06:00:03 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-18 14:15:43 +0000 (Tue, 18 Mar 2025)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2025-24813");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat RCE Vulnerability (Mar 2025) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The original implementation of partial PUT used a temporary
  file based on the user provided file name and path with the path separator replaced by '.'.

  If all of the following are true, a malicious user is able to view security sensitive files
  and/or inject content into those files:

  - writes enabled for the default servlet (disabled by default)

  - support for partial PUT (enabled by default)

  - a target URL for security sensitive uploads that is a sub-directory of a target URL for public
  uploads

  - attacker knowledge of the names of security sensitive files being uploaded

  - the security sensitive files also being uploaded via partial PUT

  If all of the following are true, a malicious user is able to perform remote code execution:

  - writes enabled for the default servlet (disabled by default)

  - support for partial PUT (enabled by default)

  - application is using Tomcat's file based session persistence with the default storage location

  - application includes a library that may be leveraged in a deserialization attack");

  script_tag(name:"affected", value:"Apache Tomcat version 9.0.98 and prior, 10.x through 10.1.34
  and 11.0.0-M1 through 11.0.2.

  Note: While not explicitly mentioned by the vendor (due to the EOL status of these branches) it
  is assumed that the whole 10.x branch and all versions prior to 9.x are affected by these flaws.
  If you disagree with this assessment and want to accept the risk please create an override for
  this result.");

  script_tag(name:"solution", value:"Update to version 9.0.99, 10.1.35, 11.0.3 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/j5fkjv2k477os90nczf2v9l61fb0kkgq");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.3");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.35");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.99");
  script_xref(name:"URL", value:"https://github.com/iSee857/CVE-2025-24813-PoC");
  script_xref(name:"URL", value:"https://lab.wallarm.com/one-put-request-to-own-tomcat-cve-2025-24813-rce-is-in-the-wild/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/03/10/5");
  script_xref(name:"URL", value:"https://scrapco.de/blog/analysis-of-cve-2025-24813-apache-tomcat-path-equivalence-rce.html");
  script_xref(name:"URL", value:"https://bishopfox.com/blog/tomcat-cve-2025-24813-what-you-need-to-know-blog");

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

if (version_is_less(version: version, test_version: "9.0.99")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.99", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.1.35")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.35", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
