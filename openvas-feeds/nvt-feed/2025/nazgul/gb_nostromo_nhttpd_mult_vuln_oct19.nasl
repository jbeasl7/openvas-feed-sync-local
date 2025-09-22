# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nazgul:nostromo_nhttpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.135008");
  script_version("2025-08-07T05:44:51+0000");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-04-28 06:50:17 +0000 (Mon, 28 Apr 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-16 13:49:19 +0000 (Wed, 16 Oct 2019)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-16278", "CVE-2019-16279");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nazgul Nostromo nhttpd < 1.9.7 Multiple Directory Traversal Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_nazgul_nostromo_nhttpd_http_detect.nasl");
  script_mandatory_keys("nazgul/nostromo_nhttpd/detected");

  script_tag(name:"summary", value:"Nazgul Nostromo nhttpd is prone to multiple directory traversal
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-16278: Attackers are able to execute arbitrary code via a crafted HTTP request due to
  directory traversal in the function http_verify.

  - CVE-2019-16279: Attackers are able to use memory error in the function SSL_accept to trigger
  denial of service via crafted HTTP request.");

  script_tag(name:"affected", value:"Nazgul Nostromo nhttpd prior to version 1.9.7.");

  script_tag(name:"solution", value:"Update to version 1.9.7 or later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/155045/Nostromo-1.9.6-Directory-Traversal-Remote-Command-Execution.html");
  script_xref(name:"URL", value:"https://www.nazgul.ch/dev/nostromo_cl.txt");

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

if (version_is_less(version: version, test_version: "1.9.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
