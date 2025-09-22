# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sixapart:movable_type";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100430");
  script_version("2025-02-21T05:37:49+0000");
  script_tag(name:"last_modification", value:"2025-02-21 05:37:49 +0000 (Fri, 21 Feb 2025)");
  script_tag(name:"creation_date", value:"2010-01-06 18:07:55 +0100 (Wed, 06 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Movable Type Unspecified Security Bypass Vulnerability (Jan 2010)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_movable_type_http_detect.nasl");
  script_mandatory_keys("sixapart/movabletype/detected");

  script_tag(name:"summary", value:"Movable Type is prone to an unspecified security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Movable Type prior to version 4.27 and 5.x prior to 5.0.1");

  script_tag(name:"solution", value:"The vendor has released fixes. Please see the references for
  more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37638");
  script_xref(name:"URL", value:"http://www.movabletype.jp/blog/movable_type_501.html");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN09872874/index.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
location = infos["location"];

if (vers =~ "^5\.") {
  if (version_is_less(version: vers, test_version: "5.01")) {
    report = report_fixed_ver(installed_version: vers, fixed_version: "5.01", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
} else if (version_is_less(version: vers, test_version: "4.27")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "4.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
