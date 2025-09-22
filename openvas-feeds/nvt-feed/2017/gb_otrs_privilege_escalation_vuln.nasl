# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812273");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-12-26 13:32:26 +0530 (Tue, 26 Dec 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-17476");

  # # Application is vulnerable only if system has cookie support disabled
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Framework Privilege Escalation Vulnerability (OSA-2017-10)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"OTRS Framework is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as when an attacker sends a specially prepared
  email to an OTRS system while system has cookie support disabled, a logged in agent clicking a
  link in this email will leak the session information to external systems.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to hijack
  web sessions and consequently gain privileges via a crafted email.");

  script_tag(name:"affected", value:"OTRS version 4.x prior to 4.0.28, 5.x prior to 5.0.26, and
  6.x prior to 6.0.3.");

  script_tag(name:"solution", value:"Update to version 4.0.28, 5.0.26, 6.0.3 or later.");

  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2017-10-security-update-otrs-framework");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.0.0", test_version_up: "4.0.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.28", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.0.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.26", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
