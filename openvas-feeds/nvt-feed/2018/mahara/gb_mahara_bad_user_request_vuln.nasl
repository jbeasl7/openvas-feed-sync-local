# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mahara:mahara";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112306");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2018-06-14 11:22:16 +0200 (Thu, 14 Jun 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-13 16:54:00 +0000 (Wed, 13 Jun 2018)");

  script_cve_id("CVE-2017-1000141");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mahara < 18.10.0 Mishandled User Requests Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mahara_http_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"summary", value:"Mahara is prone to a vulnerability dealing with mishandled user
  requests.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Mahara mishandled user requests that could discontinue a user's
  ability to maintain their own account (changing username, changing primary email address,
  deleting account).

  The correct behavior was to either prompt them for their password and/or send a warning to their
  primary email address.");

  script_tag(name:"affected", value:"Mahara prior to version 18.10.0.");

  script_tag(name:"solution", value:"Update to version 18.10.0 or later.");

  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1422492");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "18.10.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "18.10.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
