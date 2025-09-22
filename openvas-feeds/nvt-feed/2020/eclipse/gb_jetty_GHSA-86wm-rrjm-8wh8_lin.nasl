# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144926");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-11-30 06:03:22 +0000 (Mon, 30 Nov 2020)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2020-27218");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Gzip Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a vulnerability where the buffer is not correctly
  recycled in Gzip Request inflation.");

  script_tag(name:"insight", value:"If GZIP request body inflation is enabled and requests from different clients
  are multiplexed onto a single connection and if an attacker can send a request with a body that is received
  entirely by not consumed by the application, then a subsequent request on the same connection will see that body
  prepended to it's body.

  The attacker will not see any data, but may inject data into the body of the subsequent request.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eclipse Jetty versions 9.4.0.RC0 - 9.4.34.v20201102, 10.0.0.alpha0 -
  10.0.0.beta2 and 11.0.0.alpha0 - 11.0.0.beta2.");

  script_tag(name:"solution", value:"Update to versions 9.4.35.v20201120, 10.0.0.beta3, 11.0.0.beta3 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-86wm-rrjm-8wh8");
  script_xref(name:"URL", value:"https://bugs.eclipse.org/bugs/show_bug.cgi?id=568892");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",
                                          exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "9.4.0", test_version2: "9.4.34.20201102")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.35.20201120", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
