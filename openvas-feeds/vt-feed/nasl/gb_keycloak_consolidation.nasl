# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125708");
  script_version("2026-02-20T15:48:06+0000");
  script_tag(name:"last_modification", value:"2026-02-20 15:48:06 +0000 (Fri, 20 Feb 2026)");
  script_tag(name:"creation_date", value:"2026-02-11 10:20:51 +0000 (Wed, 11 Feb 2026)");;
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Keycloak Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Keycloak detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_keycloak_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_keycloak_smb_login_detect.nasl",
                        "gsf/gb_keycloak_ssh_login_detect.nasl");
  script_mandatory_keys("keycloak/detected");

  script_xref(name:"URL", value:"https://www.keycloak.org/");
  script_xref(name:"URL", value:"https://access.redhat.com/products/red-hat-build-of-keycloak");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "keycloak/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

# Handle upstream Keycloak
foreach source( make_list( "smb-login", "ssh-login", "http" ) ) {

  install_list = get_kb_list( "keycloak/upstream/" + source + "/*/installs" );
  if( ! install_list )
    continue;

  install_list = sort( install_list );

  foreach install( install_list ) {
    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    install  = infos[1];
    version  = infos[2];
    concl    = infos[3];
    conclurl = infos[5];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:redhat:keycloak:" );
    cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:keycloak:keycloak:" );
    if( ! cpe ) {
      cpe = "cpe:/a:redhat:keycloak";
      cpe2 = "cpe:/a:keycloak:keycloak";
    }

    if( source == "http" )
      source = "www";

    register_product( cpe:cpe, location:install, port:port, service:source );
    register_product( cpe:cpe2, location:install, port:port, service:source );

    if( report )
      report += '\n\n';

    report += build_detection_report( app:"Keycloak",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concluded:concl,
                                      concludedUrl:conclurl );
  }
}

# Handle Red Hat Build of Keycloak
foreach source( make_list( "smb-login", "ssh-login", "http" ) ) {

  install_list = get_kb_list( "redhat/build_of_keycloak/" + source + "/*/installs" );
  if( ! install_list )
    continue;

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

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:redhat:keycloak:" );
    cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:redhat:build_of_keycloak:" );
    if( ! cpe ) {
      cpe = "cpe:/a:redhat:keycloak";
      cpe2 = "cpe:/a:redhat:build_of_keycloak";
    }

    if( source == "http" )
      source = "www";

    register_product( cpe:cpe, location:install, port:port, service:source );
    register_product( cpe:cpe2, location:install, port:port, service:source );

    if( report )
      report += '\n\n';

    report += build_detection_report( app:"Red Hat Build of Keycloak",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concluded:concl,
                                      concludedUrl:conclurl );
  }
}

if( report )
  log_message( port:0, data:chomp( report ) );

exit( 0 );
