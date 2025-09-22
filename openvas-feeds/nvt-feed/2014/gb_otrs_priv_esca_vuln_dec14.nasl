# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805230");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2014-12-24 12:30:49 +0530 (Wed, 24 Dec 2014)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2014-9324");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 3.2.x < 3.2.17, 3.3.x < 3.3.11, 4.x < 4.0.3 Help Desk Privilege Escalation Vulnerability (Dec 2014)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) Help Desk is prone to a
  privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists due to error in the 'GenericInterface' that
  is due to a lack of sufficient permission checks.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  access to and make changes to ticket data of other users.");

  script_tag(name:"affected", value:"OTRS Help Desk versions 3.2.x prior to 3.2.17, 3.3.x prior to
  3.3.11 and 4.0.x prior to 4.0.3.");

  script_tag(name:"solution", value:"Update to version 3.2.17, 3.3.11, 4.0.3 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59875");
  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2014-06-incomplete-access-control");

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

if (version_in_range(version: version, test_version: "3.2.0", test_version2: "3.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.3.0", test_version2: "3.3.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
