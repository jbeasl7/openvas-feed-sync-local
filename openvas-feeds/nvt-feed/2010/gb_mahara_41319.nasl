# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mahara:mahara";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100697");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2010-07-05 12:40:56 +0200 (Mon, 05 Jul 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-1667", "CVE-2010-1668", "CVE-2010-1669", "CVE-2010-1670");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mahara Multiple Vulnerabilities (Jul 2010)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mahara_http_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"summary", value:"Mahara is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Multiple HTML-injections

  - Cross-site request forgery (CSRF)

  - Multiple SQL injection (SQLi)s (SQLi)

  - Authentication bypass");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to steal
  cookie-based authentication credentials, control how the site is rendered to the user, compromise
  the application, access or modify data, or exploit latent vulnerabilities in the underlying
  database, gain unauthorized access to the application and perform certain administrative
  tasks.");

  script_tag(name:"solution", value:"Update to version 1.0.15, 1.1.9, 1.2.5 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41319");
  script_xref(name:"URL", value:"http://wiki.mahara.org/Release_Notes/1.0.15");
  script_xref(name:"URL", value:"http://wiki.mahara.org/Release_Notes/1.1.9");
  script_xref(name:"URL", value:"http://wiki.mahara.org/Release_Notes/1.2.5");

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

if (version_in_range(version: version, test_version: "1.0", test_version2: "1.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.1", test_version2: "1.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.2", test_version2: "1.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
