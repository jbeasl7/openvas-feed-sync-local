# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sixapart:movable_type";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805357");
  script_version("2025-02-21T05:37:49+0000");
  script_tag(name:"last_modification", value:"2025-02-21 05:37:49 +0000 (Fri, 21 Feb 2025)");
  script_tag(name:"creation_date", value:"2015-04-10 15:04:37 +0530 (Fri, 10 Apr 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-1592");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Movable Type < 5.2.12, 6.0.x < 6.0.7 LFI Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_movable_type_http_detect.nasl");
  script_mandatory_keys("sixapart/movabletype/detected");

  script_tag(name:"summary", value:"Movable Type is prone to local file inclusion (LFI)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Movable Type does not properly use the Perl Storable::thaw
  function, which allows remote attackers to include and execute arbitrary local Perl files and
  possibly execute arbitrary code via unspecified vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow an unauthenticated remote
  attacker to upload files and execute arbitrary code in an affected site.");

  script_tag(name:"affected", value:"Movable Type prior to version 5.2.12 and 6.0.x prior to
  6.0.7.");

  script_tag(name:"solution", value:"Update to version 5.2.12, 6.0.7 or later.");

  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/#/vulnerabilities/100912");
  script_xref(name:"URL", value:"https://movabletype.org/news/2015/02/movable_type_607_and_5212_released_to_close_security_vulnera.html");

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

if (version_is_less(version: version, test_version: "5.2.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
