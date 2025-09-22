# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153235");
  script_version("2024-11-12T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-11-12 05:05:34 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-10-22 09:09:57 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-08 21:15:57 +0000 (Fri, 08 Nov 2024)");

  script_cve_id("CVE-2024-6763");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty URI Parsing Vulnerability (GHSA-qh8g-58pp-2wxh) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to an URI parsing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Eclipse Jetty includes a utility class, HttpURI, for URI/URL
  parsing.

  The HttpURI class does insufficient validation on the authority segment of a URI. However the
  behaviour of HttpURI differs from the common browsers in how it handles a URI that would be
  considered invalid if fully validated against the RRC. Specifically HttpURI and the browser may
  differ on the value of the host extracted from an invalid URI and thus a combination of Jetty and
  a vulnerable browser may be vulnerable to a open redirect attack or to a SSRF attack if the URI
  is used after passing validation checks.");

  script_tag(name:"affected", value:"Eclipse Jetty version 7.0.0 through 12.0.11.");

  script_tag(name:"solution", value:"Update to version 12.0.12 or later.");

  script_xref(name:"URL", value:"https://github.com/jetty/jetty.project/security/advisories/GHSA-qh8g-58pp-2wxh");
  script_xref(name:"URL", value:"https://www.eclipse.org//lists/jetty-announce/msg00194.html");

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

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "12.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
