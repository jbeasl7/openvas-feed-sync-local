# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_admanager_plus";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113106");
  script_version("2026-04-22T06:16:44+0000");
  script_tag(name:"last_modification", value:"2026-04-22 06:16:44 +0000 (Wed, 22 Apr 2026)");
  script_tag(name:"creation_date", value:"2018-02-08 11:30:00 +0100 (Thu, 08 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-24 15:47:02 +0000 (Fri, 24 Oct 2025)");

  script_cve_id("CVE-2017-17552");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ManageEngine ADManager Plus < 6.6 build 6620 URL Redirection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_admanager_plus_consolidation.nasl");
  script_mandatory_keys("manageengine/admanager_plus/detected");

  script_tag(name:"summary", value:"ManageEngine ADManager Plus is prone to an URL redirection attack.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker can perform a URL redirection attack via a specially
  crafted URL, specifically via the src parameter.");

  script_tag(name:"impact", value:"Successful exploitation may result in a bypass of CSRF protection
  or potentially masquerading a malicious URL as trusted.");

  script_tag(name:"affected", value:"ManageEngine ADManager Plus through version 6.6 build 6613.");

  script_tag(name:"solution", value:"Update to version 6.6 build 6620 or later.");

  script_xref(name:"URL", value:"https://umbrielsecurity.wordpress.com/2018/01/31/dangerous-url-redirection-and-csrf-in-zoho-manageengine-ad-manager-plus-cve-2017-17552/");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/ad-manager/release-notes.html");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( !infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

vers = eregmatch(pattern: "([0-9]+\.[0-9])([0-9]+)", string: version);
if (!isnull(vers[1])) {
  rep_vers = vers[1];
  build = vers[2];
}

if( version_is_less_equal( version: version, test_version: "6.66613" ) ) {
  report = report_fixed_ver( installed_version: rep_vers, installed_build: build,
                             fixed_version: "6.6", fixed_build: "6620", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
