# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810966");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-06-28 17:04:45 +0530 (Wed, 28 Jun 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-27 19:23:35 +0000 (Thu, 27 Jun 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-8735", "CVE-2016-3427");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat RCE Vulnerability (Nov 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in
  'JmxRemoteLifecycleListener'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code.");

  script_tag(name:"affected", value:"Apache Tomcat before 6.0.48, 7.x before 7.0.73, 8.x before
  8.0.39, 8.5.x before 8.5.7, and 9.x before 9.0.0.M12.

  Note: This issue exists if JmxRemoteLifecycleListener is used and an attacker
  can reach JMX ports.");

  script_tag(name:"solution", value:"Update to version 6.0.48, 7.0.73, 8.0.39, 8.5.8, 9.0.0.M13 or
  later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/502");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-6.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "6.0.48")) {
  fix = "6.0.48";
}

else if(version =~ "^7\." && version_is_less(version: version, test_version: "7.0.73")) {
  fix = "7.0.73";
}

else if(version =~ "^8\.5\." && version_is_less(version: version, test_version: "8.5.8")) {
  fix = "8.5.8";
}

else if(version =~ "^8\.0\." && version_is_less(version: version, test_version: "8.0.39")) {
  fix = "8.0.39";
}

else if(version =~ "^9\." && revcomp(a: version, b: "9.0.0.M13") < 0) {
  fix = "9.0.0-M13";
}

if(fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
