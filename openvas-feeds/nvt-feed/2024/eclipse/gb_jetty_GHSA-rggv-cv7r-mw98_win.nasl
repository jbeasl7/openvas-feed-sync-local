# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151837");
  script_version("2025-02-10T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-02-10 05:38:01 +0000 (Mon, 10 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-02-27 02:43:50 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-07 17:36:41 +0000 (Fri, 07 Feb 2025)");

  script_cve_id("CVE-2024-22201");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty DoS Vulnerability (GHSA-rggv-cv7r-mw98) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If an HTTP/2 connection gets TCP congested, when an idle
  timeout occurs the HTTP/2 session is marked as closed, and then a GOAWAY frame is queued to be
  written. However it is not written because the connection is TCP congested. When another idle
  timeout period elapses, it is then supposed to hard close the connection, but it delegates to the
  HTTP/2 session which reports that it has already been closed so it does not attempt to hard close
  the connection.

  This leaves the connection in ESTABLISHED state (i.e. not closed), TCP congested, and idle.

  An attacker can cause many connections to end up in this state, and the server may run out of
  file descriptors, eventually causing the server to stop accepting new connections from valid
  clients.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.3.0 through 9.4.53, 10.0.0 through
  10.0.19, 11.0.0 through 11.0.19 and 12.0.0 through 12.0.5.");

  script_tag(name:"solution", value:"Update to version 9.4.54, 10.0.20, 11.0.20, 12.0.6 or later.");

  script_xref(name:"URL", value:"https://github.com/jetty/jetty.project/security/advisories/GHSA-rggv-cv7r-mw98");

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

if (version_in_range_exclusive(version: version, test_version_lo: "9.3.0", test_version_up: "9.4.54")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.54", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.0.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "12.0.0", test_version_up: "12.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
