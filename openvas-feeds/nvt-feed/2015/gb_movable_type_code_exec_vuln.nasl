# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sixapart:movable_type";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805368");
  script_version("2025-02-21T05:37:49+0000");
  script_tag(name:"last_modification", value:"2025-02-21 05:37:49 +0000 (Fri, 21 Feb 2025)");
  script_tag(name:"creation_date", value:"2015-04-13 18:43:00 +0530 (Mon, 13 Apr 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-2184");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Movable Type < 5.2.6 Arbitrary Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_movable_type_http_detect.nasl");
  script_mandatory_keys("sixapart/movabletype/detected");

  script_tag(name:"summary", value:"Movable Type is prone to an arbitrary code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the Perl Storable::thaw function which
  allows remote attackers to include and execute arbitrary local Perl files and possibly execute
  arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation will allow an unauthenticated remote
  attacker to upload files and execute arbitrary code in an affected site.");

  script_tag(name:"affected", value:"Movable Type prior to version 5.2.6.");

  script_tag(name:"solution", value:"Update to version 5.2.6 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q2/560");
  script_xref(name:"URL", value:"https://movabletype.org/documentation/appendices/release-notes/movable-type-526-release-notes.html");

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

if (version_is_less(version: version, test_version: "5.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
