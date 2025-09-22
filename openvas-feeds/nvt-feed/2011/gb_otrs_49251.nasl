# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103216");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-08-22 16:04:33 +0200 (Mon, 22 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2011-2746");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Local File Disclosure Vulnerability (OSA-2011-03)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to a local file
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in application which fails to adequately
  validate user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this vulnerability would allow an attacker to obtain
  potentially sensitive information from local files on computers running the vulnerable
  application. This may aid in further attacks.");

  script_tag(name:"affected", value:"OTRS versions 2.4.x prior to 2.4.11 and 3.x prior to
  3.0.8.");

  script_tag(name:"solution", value:"Update to version 2.4.11, 3.0.8 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49251");
  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2011-03-en/");

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

if (version_in_range(version: version, test_version: "2.4.0", test_version2: "2.4.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
