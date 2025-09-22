# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151004");
  script_version("2025-05-28T05:40:15+0000");
  script_tag(name:"last_modification", value:"2025-05-28 05:40:15 +0000 (Wed, 28 May 2025)");
  script_tag(name:"creation_date", value:"2023-09-19 04:55:19 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-27 21:20:37 +0000 (Tue, 27 May 2025)");

  script_cve_id("CVE-2023-36479");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty CgiServlet Vulnerability (GHSA-3gh6-v5v9-6v9j) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a vulnerability in the CgiServlet.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Users of the CgiServlet with a very specific command structure
  may have the wrong command executed. If a user sends a request to a
  org.eclipse.jetty.servlets.CGI Servlet for a binary with a space in its name, the servlet will
  escape the command by wrapping it in quotation marks. This wrapped command, plus an optional
  command prefix, will then be executed through a call to Runtime.exec. If the original binary name
  provided by the user contains a quotation mark followed by a space, the resulting command line
  will contain multiple tokens instead of one.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.0.0 through 9.4.51, 10.0.0 through
  10.0.15 and 11.0.0 through 11.0.15.");

  script_tag(name:"solution", value:"Update to version 9.4.52, 10.0.16, 11.0.16 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-3gh6-v5v9-6v9j");

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

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0", test_version_up: "9.4.52")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.52", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
