# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pi-hole:web_interface";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145120");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-01-12 09:19:25 +0000 (Tue, 12 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-28 17:40:00 +0000 (Mon, 28 Dec 2020)");

  script_cve_id("CVE-2020-35659");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pi-hole Web Interface < 5.2.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pi-hole_http_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"The Pi-hole Web Interface (previously AdminLTE) is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The DNS query log in Pi-hole is vulnerable to stored XSS. An
  attacker with the ability to directly or indirectly query DNS with a malicious hostname can cause
  arbitrary JavaScript to execute when the Pi-hole administrator visits the Query Log or Long-term
  data Query Log page.");

  script_tag(name:"affected", value:"Pi-hole Web Interface (previously AdminLTE) version 5.2.1 and
  probably prior.");

  script_tag(name:"solution", value:"Update to version 5.2.2 or later.");

  script_xref(name:"URL", value:"https://discourse.pi-hole.net/t/pi-hole-core-web-v5-2-2-and-ftl-v5-3-4-released/41998");
  script_xref(name:"URL", value:"https://blog.mirch.io/2020/12/24/pihole-xss/");

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

if (version_is_less(version: version, test_version: "5.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
