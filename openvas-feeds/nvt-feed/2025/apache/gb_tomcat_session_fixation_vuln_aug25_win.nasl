# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127943");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-19 10:04:57 +0000 (Tue, 19 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-55668");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Session Fixation Vulnerability (Aug 2025) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a session fixation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If the rewrite valve was enabled for a web application, an
  attacker was able to craft a URL that, if a victim clicked on it, would cause the  victim's
  interaction with that resource to occur in the context of the attacker's session.");

  script_tag(name:"affected", value:"Apache Tomcat versions prior to 9.0.106, 10.1.0-M1 through
  10.1.41 and 11.0.0-M1 through 11.0.7.");

  script_tag(name:"solution", value:"Update to version 9.0.106, 10.1.42, 11.0.8 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/v6bknr96rl7l1qxkl1c03v0qdvbbqs47");

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

if (version_in_range(version: version, test_version: "10.1.0.M1", test_version2: "10.1.41")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.42", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0.0.M1", test_version2: "11.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
