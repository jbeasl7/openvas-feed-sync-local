# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103933");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2014-04-03 12:44:23 +0200 (Thu, 03 Apr 2014)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-2553", "CVE-2014-2554");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Help Desk Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"OTRS Help Desk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-2553: Certain input related to dynamic fields is not properly sanitised before being
  returned to the user. This can be exploited to execute arbitrary HTML and script code in a user's
  browser session in context of an affected site.

  - CVE-2014-2554: The application allows users to perform certain actions via HTTP requests via
  iframes without performing any validity checks to verify the requests. This can be exploited to
  perform certain unspecified actions by tricking a user into e.g. clicking a specially crafted link
  via clickjacking.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"OTRS Help Desk versions 3.1.x prior to 3.1.21, 3.2.x prior to
  3.2.16 and 3.3.x prior to 3.3.6.");

  script_tag(name:"solution", value:"Update to version 3.1.21, 3.2.16, 3.3.6 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66569");
  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2014-04-xss-issue");
  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2014-05-clickjacking-issue/");

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
