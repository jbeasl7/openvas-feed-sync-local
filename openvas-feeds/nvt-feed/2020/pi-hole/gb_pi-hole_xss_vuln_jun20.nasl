# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pi-hole:web_interface";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144172");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2020-06-26 06:12:34 +0000 (Fri, 26 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-05 14:41:00 +0000 (Wed, 05 Aug 2020)");

  script_cve_id("CVE-2020-14971", "CVE-2020-14162");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pi-hole Web Interface < 5.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pi-hole_http_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"The Pi-hole Web Interface (previously AdminLTE) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-14971: Cross-site scripting (XSS) in piholedhcp

  - CVE-2020-14162: Privilege escalation via shell metacharacters");

  script_tag(name:"affected", value:"Pi-hole Web Interface (previously AdminLTE) version 5.0 and
  prior.");

  script_tag(name:"solution", value:"Update to version 5.1 or later.");

  script_xref(name:"URL", value:"https://github.com/pi-hole/AdminLTE/pull/1443");
  script_xref(name:"URL", value:"https://blog.telspace.co.za/2020/06/pi-hole-code-injection-cve-2020-14971.html");
  script_xref(name:"URL", value:"https://0xpanic.github.io/2020/07/21/Pihole.html");
  script_xref(name:"URL", value:"https://pi-hole.net/2020/07/15/pi-hole-5-1-released");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
