# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154398");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2025-04-29 03:04:57 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-05 20:12:54 +0000 (Mon, 05 May 2025)");

  script_cve_id("CVE-2025-31650");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat DoS Vulnerability (Apr 2025) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Incorrect error handling for some invalid HTTP priority headers
  results in incomplete clean-up of the failed request which creates a memory leak. A large number
  of such requests could trigger an OutOfMemoryException resulting in a denial of service.");

  script_tag(name:"affected", value:"Apache Tomcat version 9.0.76 through 9.0.102, 10.1.10 through
  10.1.39 and 11.0.0-M2 through 11.0.5.");

  script_tag(name:"solution", value:"Update to version 9.0.104, 10.1.40, 11.0.6 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/j6zzk0y3yym9pzfzkq5vcyxzz0yzh826");
  script_xref(name:"URL", value:"https://github.com/tunahantekeoglu/CVE-2025-31650");

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

if (version_in_range(version: version, test_version: "9.0.76", test_version2: "9.0.102")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.104", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.1.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.40", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0.M2", test_version_up: "11.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
