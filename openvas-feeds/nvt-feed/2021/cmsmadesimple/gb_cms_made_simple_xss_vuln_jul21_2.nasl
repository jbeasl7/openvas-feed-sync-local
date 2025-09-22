# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118144");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-08-06 16:22:04 +0200 (Fri, 06 Aug 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-30 15:08:00 +0000 (Fri, 30 Jul 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2020-23240");

  script_name("CMS Made Simple 2.2.14 XSS Vulnerability (Jul 2021)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated malicious user can take advantage of a stored XSS
  vulnerability on on 'Logic' via 'Content Manager'.

  Vendor statement: 'The Logic field is meant to put code in and it is only accessible for approved
  administrators'.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  transmit private data, like cookies or other session information, redirecting the victim to web
  content controlled by the attacker, or performing other malicious operations on the user's machine
  under the guise of the vulnerable site.");

  script_tag(name:"affected", value:"CMS Made Simple prior to version 2.2.15.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Note: The vendor states: 'The Logic field is meant to put code in and it is only accessible
  for approved administrators. If you don't trust your admins, don't give them access to
  (this field in) the admin panel.'");

  script_xref(name:"URL", value:"http://dev.cmsmadesimple.org/bug/view/12321");

  exit(0);
}

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_equal( version: version, test_version: "2.2.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 0 );
