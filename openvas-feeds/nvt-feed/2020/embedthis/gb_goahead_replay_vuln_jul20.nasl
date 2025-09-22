# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:embedthis:goahead";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113734");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2020-07-28 09:55:09 +0000 (Tue, 28 Jul 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-07 18:15:00 +0000 (Wed, 07 Oct 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-15688");

  script_name("Embedthis GoAhead < 4.1.4, 5.x < 5.1.2 Replay Attack Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_embedthis_goahead_http_detect.nasl");
  script_mandatory_keys("embedthis/goahead/detected");

  script_tag(name:"summary", value:"Embedthis GoAhead is prone to a replay attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists because GoAhead mishandles the nonce
  value during Digest authentication.");

  script_tag(name:"affected", value:"Embedthis GoAhead versions through 4.1.3 and 5.x through
  5.1.1.");

  script_tag(name:"solution", value:"Update to version 4.1.4, 5.1.2 or later.");

  script_xref(name:"URL", value:"https://github.com/embedthis/goahead-gpl/issues/3");

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

if( version_is_less( version: version, test_version: "4.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.1.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
