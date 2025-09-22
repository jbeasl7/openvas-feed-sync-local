# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113061");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-12-06 14:32:33 +0100 (Wed, 06 Dec 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-29 16:16:00 +0000 (Mon, 29 Apr 2019)");

  # nb: There are no backports of the affected versions
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-1000217");

  script_name("Opencast <= 2.3.2 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_opencast_detect.nasl");
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"Opencast through version 2.3.2 is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Opencast allows for script injections through media and metadata
  in the player and medial module.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute
  arbitrary code on the target host.");

  script_tag(name:"affected", value:"Opencast through version 2.3.2.");

  script_tag(name:"solution", value:"Update to version 2.3.3, 3.0 or later.");

  script_xref(name:"URL", value:"https://groups.google.com/a/opencast.org/forum/#!topic/security-notices/sCpt0pIPEFg");

  exit(0);
}

CPE = "cpe:/a:opencast:opencast";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_is_less_equal( version: version, test_version: "2.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.3" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
