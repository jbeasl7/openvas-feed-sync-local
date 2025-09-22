# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803947");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-09-28 13:08:01 +0530 (Sat, 28 Sep 2013)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2008-1515");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 2.1.x < 2.1.8, 2.2.x < 2.2.6 SOAP Security Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to a security
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in SOAP interface which fails to properly
  validate user credentials before performing certain actions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read and
  modify objects via the OTRS SOAP interface.");

  script_tag(name:"affected", value:"OTRS version 2.1.x prior to 2.1.8 and 2.2.x prior to
  2.2.6.");

  script_tag(name:"solution", value:"Update to version 2.1.8, 2.2.6 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74733");

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

if (version_in_range(version: version, test_version: "2.1.0", test_version2: "2.1.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.2.0", test_version2: "2.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
