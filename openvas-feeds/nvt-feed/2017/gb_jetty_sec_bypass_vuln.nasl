# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140261");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-08-01 11:31:21 +0700 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-15 14:55:00 +0000 (Tue, 15 Mar 2022)");
  script_cve_id("CVE-2017-9735");
  script_name("Jetty < 9.4.6.20170531 Security Bypass Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/issues/1556");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99104");

  script_tag(name:"summary", value:"Jetty is prone to a security bypass vulnerability.");

  script_tag(name:"insight", value:"Jetty through is prone to a timing channel in util/security/Password.java,
  which makes it easier for remote attackers to obtain access by observing elapsed times before rejection of
  incorrect passwords.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Jetty version 9.4.x.");

  script_tag(name:"solution", value:"Update to version 9.4.6.v20170531 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+", exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version =~ "^9\.4\.") {
  if (version_is_less(version: version, test_version: "9.4.6.20170531")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.4.6.20170531", install_path: path);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
