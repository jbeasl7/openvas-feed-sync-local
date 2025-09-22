# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104550");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2023-02-21 08:56:33 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-01 15:09:00 +0000 (Wed, 01 Mar 2023)");

  script_cve_id("CVE-2023-24998");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat DoS Vulnerability (Feb 2023) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache Tomcat uses a packaged renamed copy of Apache Commons
  FileUpload to provide the file upload functionality defined in the Jakarta Servlet specification.
  Apache Tomcat was, therefore, also vulnerable to the Apache Commons FileUpload vulnerability
  CVE-2023-24998 as there was no limit to the number of request parts processed. This resulted in
  the possibility of an attacker triggering a DoS with a malicious upload or series of uploads.");

  script_tag(name:"affected", value:"Apache Tomcat versions through 8.5.84, 9.0.0-M1 through 9.0.70,
  10.x through 10.1.4 and 11.0.0-M1 only.");

  script_tag(name:"solution", value:"Update to version 8.5.85, 9.0.71, 10.1.5, 11.0.0-M3 or
  later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/g16kv0xpp272htz107molwbbgdrqrdk1");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M3");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.5");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.71");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.85");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/4xl4l09mhwg4vgsk7dxqogcjrobrrdoy");

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

# nb: Using version_is_less() here on purpose for the similar reason given for 10.0.x below.
if (version_is_less(version: version, test_version: "8.5.85")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.85", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0.M1", test_version_up: "9.0.71")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.71", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

# nb: 10.0.x has been used as the lower bound here on purpose vs. 10.1.x as it is unlikely that
# 9.0.0+ and 10.1.0+ was affected but 10.0.x not. More likely the vendor just doesn't mention 10.0.x
# in the advisory anymore because it might be EOL and haven't been evaluated at all or similar...
if (version_in_range_exclusive(version: version, test_version_lo: "10.0", test_version_up: "10.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "11.0.0.M1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.0-M3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
