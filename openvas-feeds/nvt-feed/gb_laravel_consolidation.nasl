# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.135014");
  script_version("2025-07-30T05:45:23+0000");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-05-24 11:20:11 +0000 (Sat, 24 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Laravel Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_laravel_http_detect.nasl", "gb_laravel_ssh_login_detect.nasl");
  script_mandatory_keys("laravel/detected");

  script_tag(name:"summary", value:"Consolidation of Laravel detections.");

  script_xref(name:"URL", value:"https://laravel.com/");

  exit(0);
}

if( ! get_kb_item( "laravel/detected" ) && ! get_kb_item( "laravel/telescope/detected" ) )
  exit( 0 );

include("host_details.inc");
include("cpe.inc");

report = "";

foreach source( make_list( "ssh-login", "http", "telescope/http" ) ) {

  install_list = get_kb_list( "laravel/" + source + "/*/installs" );
  if( ! install_list )
    continue;

  install_list = sort( install_list );

  foreach install( install_list ) {

    infos = split( install, sep: "#---#", keep: FALSE );
    if( max_index( infos ) < 3 )
      continue;

    port      = infos[0];
    install   = infos[1];
    version   = infos[2];
    concl     = infos[3];
    concl_url = infos[4];
    extra     = infos[5];

    cpe = build_cpe( value: version, exp: "^([.0-9]+)", base: "cpe:/a:laravel:laravel:" );
    if( ! cpe )
      cpe = "cpe:/a:laravel:laravel";

    if( report )
      report += '\n\n';

    app_name = "Laravel Framework";
    if( source == "telescope/http" )
      app_name = "Laravel Telescope";

    if( source == "http" || source == "telescope/http" )
      source = "www";

    register_product( cpe: cpe, location: install, port: port, service: source );
    report += build_detection_report( app: app_name,
                                      version: version,
                                      install: install,
                                      concluded: concl,
                                      cpe: cpe,
                                      extra: extra,
                                      concludedUrl: concl_url );
  }
}

if( report )
  log_message( port: port, data: report );

exit( 0 );
