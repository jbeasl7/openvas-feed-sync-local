# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100821");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2010-09-22 16:24:51 +0200 (Wed, 22 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2010-2080", "CVE-2010-3476");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Core System Multiple Vulnerabilities (OSA-2010-02)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to multiple
  cross-site scripting (XSS) vulnerabilities and a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in application which fails to properly handle
  user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to cause denial of
  service conditions or to execute arbitrary script code in the browser of an unsuspecting user in
  the context of the affected site.");

  script_tag(name:"affected", value:"OTRS versions prior to 2.3.6 and 2.4.x prior to 2.4.8.");

  script_tag(name:"solution", value:"Update to version 2.3.6, 2.4.8 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43264");
  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2010-02-en/");

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

if (version_is_less(version: version, test_version: "2.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.4.0", test_version_up: "2.4.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
