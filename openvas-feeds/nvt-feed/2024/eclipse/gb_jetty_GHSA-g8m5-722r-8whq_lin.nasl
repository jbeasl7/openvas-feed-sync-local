# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153228");
  script_version("2024-11-12T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-11-12 05:05:34 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-10-22 08:38:09 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-08 21:00:09 +0000 (Fri, 08 Nov 2024)");

  script_cve_id("CVE-2024-8184");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty DoS Vulnerability (GHSA-g8m5-722r-8whq) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There exists a security vulnerability in Jetty's
  ThreadLimitHandler.getRemote() which can be exploited by unauthorized users to cause remote
  denial of service (DoS) attack. By repeatedly sending crafted requests, attackers can trigger
  OutofMemory errors and exhaust the server's memory.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.3.12 through 9.4.55, 10.0.0 through
  10.0.23, 11.0.0 through 11.0.23 and 12.0.0 through 12.0.8.");

  script_tag(name:"solution", value:"Update to version 9.4.56, 10.0.24, 11.0.24, 12.0.9 or later.");

  script_xref(name:"URL", value:"https://github.com/jetty/jetty.project/security/advisories/GHSA-g8m5-722r-8whq");
  script_xref(name:"URL", value:"https://www.eclipse.org//lists/jetty-announce/msg00193.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "9.3.12", test_version_up: "9.4.56")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.56", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.0.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "12.0.0", test_version_up: "12.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
