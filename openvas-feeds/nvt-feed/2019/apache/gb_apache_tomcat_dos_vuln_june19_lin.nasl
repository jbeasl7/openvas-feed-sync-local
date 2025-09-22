# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142811");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-08-28 07:47:49 +0000 (Wed, 28 Aug 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_cve_id("CVE-2019-10072");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat DoS Vulnerability (Jun 2019) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"The fix for CVE-2019-0199 was incomplete and did not address HTTP/2 connection
  window exhaustion on write. By not sending WINDOW_UPDATE messages for the connection window (stream 0) clients
  are able to cause server-side threads to block eventually leading to thread exhaustion and a DoS.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat versions 8.5.0 to 8.5.40 and 9.0.0.M1 to 9.0.19.");

  script_tag(name:"solution", value:"Update to version 8.5.41, 9.0.20 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/df1a2c1b87c8a6c500ecdbbaf134c7f1491c8d79d98b48c6b9f0fa6a@%3Cannounce.tomcat.apache.org%3E");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108874");

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

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.41", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0.M1") >= 0) && (revcomp(a: version, b: "9.0.19") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.20", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
