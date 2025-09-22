# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpbb:phpbb";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112836");
  script_version("2025-06-18T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-06-18 05:40:25 +0000 (Wed, 18 Jun 2025)");
  script_tag(name:"creation_date", value:"2020-11-10 14:17:12 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2020-11-10 00:00:00 +0000 (Tue, 10 Nov 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpBB End of Life (EOL) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("phpbb_detect.nasl");
  script_mandatory_keys("phpBB/installed");

  script_tag(name:"summary", value:"The installed version of phpBB on the remote host has reached the End of Life (EOL) and
  should not be used anymore.");

  script_tag(name:"impact", value:"An EOL version of phpBB is not receiving any security updates from
  the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise the security of
  this host.");

  script_tag(name:"solution", value:"Update phpBB on the remote host to a still supported version.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?t=2373956");
  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?f=14&p=14902381#p14902381");
  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?f=14&t=2573411");
  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?f=14&t=1385785");

  exit(0);
}

include("host_details.inc");
include("date_func.inc");
include("eol_product.inc");
include("eol_shared.inc");
include("list_array_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version  = infos["version"];
location = infos["location"];

if(ret = product_reached_eol(cpe: CPE, version: version)) {
  report = eol_build_message(name: "phpBB", cpe: CPE, version: version,
                             location: location,
                             eol_version: ret["eol_version"],
                             eol_date: ret["eol_date"],
                             eol_type: "prod");

  security_message(port: port, data: report);
  exit(0);
}

exit(99);
