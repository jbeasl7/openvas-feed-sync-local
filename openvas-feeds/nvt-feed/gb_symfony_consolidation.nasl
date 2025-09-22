# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107325");
  script_version("2024-12-05T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-12-05 05:05:31 +0000 (Thu, 05 Dec 2024)");
  script_tag(name:"creation_date", value:"2018-06-26 16:20:53 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sensiolabs Symfony Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_symfony_http_detect.nasl", "gb_symfony_ssh_login_detect.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Consolidation of Sensiolabs Symfony detections.");

  script_xref(name:"URL", value:"https://symfony.com/");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "symfony/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "ssh-login", "http" ) ) {

  install_list = get_kb_list( "symfony/" + source + "/*/installs" );
  if( ! install_list )
    continue;

  foreach install( install_list ) {

    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port = infos[0];
    location = infos[1];
    version = infos[2];
    concluded = infos[3];
    concludedUrl = infos[4];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:sensiolabs:symfony:" );
    if( ! cpe )
      cpe = "cpe:/a:sensiolabs:symfony";

    service = source;
    if( service == "http" )
      service = "www";

    register_product( cpe:cpe, location:location, port:port, service:service );

    if( report )
      report += '\n\n';
    report += build_detection_report( app:"Sensiolabs Symfony Framework",
                                      version:version,
                                      install:location,
                                      cpe:cpe,
                                      concludedUrl:concludedUrl,
                                      concluded:concluded );
  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );
