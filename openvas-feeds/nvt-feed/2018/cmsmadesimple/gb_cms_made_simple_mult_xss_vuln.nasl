# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113132");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-03-14 10:38:33 +0100 (Wed, 14 Mar 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-29 12:05:00 +0000 (Thu, 29 Mar 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-7893", "CVE-2018-8058");

  script_name("CMS Made Simple <= 2.2.6 Multiple Stored XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple stored cross-site scripting
  (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"CMS Made Simple has stored XSS vulnerabilities in
  admin/moduleinterface.php via following parameters:

  - metadata

  - pagedata");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject HTML or
  JavaScript into the website.");

  script_tag(name:"affected", value:"CMS Made Simple through version 2.2.6.");

  script_tag(name:"solution", value:"Update to version 2.2.7 or later.");

  script_xref(name:"URL", value:"https://github.com/ibey0nd/CVE/blob/master/CMS%20Made%20Simple%20Stored%20XSS.md");
  script_xref(name:"URL", value:"https://github.com/ibey0nd/CVE/blob/master/CMS%20Made%20Simple%20Stored%20XSS%202.md");

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

if( version_is_less_equal( version: version, test_version: "2.2.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
