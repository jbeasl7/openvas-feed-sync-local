# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112301");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-06-11 13:06:00 +0200 (Mon, 11 Jun 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-12 14:53:00 +0000 (Thu, 12 Jul 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-9177", "CVE-2018-9182");

  script_name("Twonky Server < 8.5.1 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_twonky_server_detect.nasl");
  script_mandatory_keys("twonky/server/detected");

  script_tag(name:"summary", value:"Twonky Server is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - XSS via a folder name on the Shared Folders screen.

  - XSS via a modified 'language' parameter in the Language section.");

  script_tag(name:"affected", value:"Twonky Server through 8.5.");

  script_tag(name:"solution", value:"Update to version 8.5.1 or later.");

  script_xref(name:"URL", value:"https://gist.github.com/prafagr/bd641fcfe71661065e659672c737173b");
  script_xref(name:"URL", value:"https://gist.github.com/priyanksethi/08fb93341cf7e61344aad5c4fee3aa9b");

  exit(0);
}

CPE = "cpe:/a:twonky:twonky_server";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_is_less( version: version, test_version: "8.5.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.5.1" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
