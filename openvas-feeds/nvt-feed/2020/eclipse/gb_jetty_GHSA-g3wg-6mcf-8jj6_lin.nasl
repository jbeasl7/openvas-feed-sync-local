# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144836");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-10-27 03:41:18 +0000 (Tue, 27 Oct 2020)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2020-27216");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Privilege Escalation Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to a privilege escalation vulnerability through a
  local temp directory.");

  script_tag(name:"insight", value:"On Unix like systems, the system's temporary directory is shared between all
  users on that system. A collocated user can observe the process of creating a temporary sub directory in the
  shared temporary directory and race to complete the creation of the temporary subdirectory. If the attacker wins
  the race then they will have read and write permission to the subdirectory used to unpack web applications,
  including their WEB-INF/lib jar files and JSP files. If any code is ever executed out of this temporary
  directory, this can lead to a local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.4.32.v20200930 and prior, 10.0.0.beta2 and prior and
  11.0.0.beta2 and prior.");

  script_tag(name:"solution", value:"Update to version 9.4.33.v20201020, 10.0.0.beta3, 11.0.0.beta3 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-g3wg-6mcf-8jj6");
  script_xref(name:"URL", value:"https://bugs.eclipse.org/bugs/show_bug.cgi?id=567921");

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

if (version_is_less(version: version, test_version: "9.4.33.20201020")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.33.20201020", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
