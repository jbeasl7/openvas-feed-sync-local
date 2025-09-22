# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902352");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-4071");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS XSS Vulnerability (OSA-2010-03)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to input passed via HTML e-mails is not
  properly sanitised in AgentTicketZoom before being displayed to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site when malicious data is being viewed.");

  script_tag(name:"affected", value:"OTRS versions 2.4.x prior to 2.4.9.");

  script_tag(name:"solution", value:"Update to version 2.4.9 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41978");
  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2010-03-en/");

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

if (version_in_range(version: version, test_version: "2.4.0", test_version2: "2.4.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
