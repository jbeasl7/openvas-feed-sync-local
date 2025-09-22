# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154754");
  script_version("2025-06-24T05:41:22+0000");
  script_tag(name:"last_modification", value:"2025-06-24 05:41:22 +0000 (Tue, 24 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-17 02:05:59 +0000 (Tue, 17 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-48976", "CVE-2025-48988", "CVE-2025-49125");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Multiple Vulnerabilities (Jun 2025) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-48976: Denial of service (DoS) in Apache Commons FileUpload

  - CVE-2025-48988: DoS in multipart upload

  - CVE-2025-49125: Security constraint bypass for pre/post-resources");

  script_tag(name:"affected", value:"Apache Tomcat version 9.0.105 and prior, 10.x through
  10.1.41 and 11.0.0-M1 through 11.0.7.

  Note: While not explicitly mentioned by the vendor (due to the EOL status of these branches) it
  is assumed that the whole 10.x branch and all versions prior to 9.x are affected by these flaws.
  If you disagree with this assessment and want to accept the risk please create an override for
  this result.");

  script_tag(name:"solution", value:"Update to version 9.0.106, 10.1.42, 11.0.8 or later.");

  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.8");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.42");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.106");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/nzkqsok8t42qofgqfmck536mtyzygp18");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/m66cytbfrty9k7dc4cg6tl1czhsnbywk");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/06/16/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/06/16/2");
  script_xref(name:"URL", value:"https://github.com/Samb102/POC-CVE-2025-48988-CVE-2025-48976");

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

if (version_is_less(version: version, test_version: "9.0.106")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.106", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.1.42")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.42", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0.M1", test_version_up: "11.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
