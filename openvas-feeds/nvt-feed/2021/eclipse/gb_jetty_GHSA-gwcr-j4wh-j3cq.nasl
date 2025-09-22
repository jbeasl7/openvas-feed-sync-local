# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146099");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2021-06-09 07:55:58 +0000 (Wed, 09 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-04 16:15:00 +0000 (Sun, 04 Jul 2021)");

  script_cve_id("CVE-2021-28169");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Information Disclosure Vulnerability (GHSA-gwcr-j4wh-j3cq)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl");
  script_mandatory_keys("jetty/detected");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to an information disclosure vulnerability
  in the ConcatServlet and WelcomeFilter servlet.");

  script_tag(name:"insight", value:"Requests to the ConcatServlet and WelcomeFilter are able to
  access protected resources within the WEB-INF directory. For example a request to the
  ConcatServlet with a URI of /concat?/%2557EB-INF/web.xml can retrieve the web.xml file. This can
  reveal sensitive information regarding the implementation of a web application.

  This occurs because both ConcatServlet and WelcomeFilter decode the supplied path to verify it is
  not within the WEB-INF or META-INF directories. It then uses this decoded path to call
  RequestDispatcher which will also do decoding of the path. This double decoding allows paths with
  a doubly encoded WEB-INF to bypass this security check.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eclipse Jetty prior to version 9.4.41, 10.x through 10.0.2 and
  11.x through 11.0.2.");

  script_tag(name:"solution", value:"Update to version 9.4.41, 10.0.3, 11.0.3 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-gwcr-j4wh-j3cq");

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

if (version_is_less(version: version, test_version: "9.4.41")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.41", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
