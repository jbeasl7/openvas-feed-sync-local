# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171722");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-19 12:38:33 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("PHP Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_dependencies("gb_php_http_detect.nasl", "gb_php_ssh_login_detect.nasl",
                      "gb_php_smb_login_detect.nasl");
  script_mandatory_keys("php/detected");

  script_xref(name:"URL", value:"https://www.php.net/");

  script_tag(name:"summary", value:"Consolidation of PHP detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "php/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "ssh-login", "smb-login", "http" ) ) {

  install_list = get_kb_list( "php/" + source + "/*/installs" );
  if( ! install_list )
    continue;

  # nb: Note that sorting the array above is currently dropping the named array index
  install_list = sort( install_list );

  foreach install( install_list ) {

    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    install  = infos[1];
    version  = infos[2];
    concl    = infos[3];
    conclurl = infos[4];

    cpe = build_cpe( value:version, exp:"^([0-9.A-Za-z]+)", base:"cpe:/a:php:php:" );
    if( ! cpe )
      cpe = "cpe:/a:php:php";

    if( source == "http" )
      source = "www";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';
    report += build_detection_report( app:"PHP",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concluded:concl,
                                      concludedUrl:conclurl );
  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );