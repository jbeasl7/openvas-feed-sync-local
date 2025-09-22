# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804418");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2014-04-07 15:00:42 +0530 (Mon, 07 Apr 2014)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-2553", "CVE-2014-2554");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Help Desk 3.1.x < 3.1.21, 3.2.x < 3.2.16, 3.3.x < 3.3.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-2553: Certain input related to dynamic fields is not properly sanitised before being
  returned to the user

  - CVE-2014-2554: The application allows users to perform certain actions via HTTP requests via
  iframes without performing any validity checks to verify the requests");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct XSS and
  clickjacking attacks.");

  script_tag(name:"affected", value:"OTRS versions 3.1.x prior to 3.1.21, 3.2.x prior to 3.2.16
  and 3.3.x prior to 3.3.6.");

  script_tag(name:"solution", value:"Update to version 3.1.21, 3.2.16, 3.3.6 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57616");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66567");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66569");
  script_xref(name:"URL", value:"http://bugs.otrs.org/show_bug.cgi?id=10361");
  script_xref(name:"URL", value:"http://bugs.otrs.org/show_bug.cgi?id=10374");

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

if (version_in_range(version: version, test_version: "3.1.0", test_version2: "3.1.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.2.0", test_version2: "3.2.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.3.0", test_version2: "3.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
