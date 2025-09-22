# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128025");
  script_version("2024-07-19T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-06-20 12:08:23 +0000 (Thu, 20 Jun 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("PostgreSQL Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_dependencies("gb_postgresql_smb_login_detect.nasl", "gb_postgresql_ssh_login_detect.nasl",
                      "gb_postgresql_tcp_detect.nasl");
  script_mandatory_keys("postgresql/detected");

  script_xref(name:"URL", value:"https://www.postgresql.org/");

  script_tag(name:"summary", value:"Consolidation of PostgreSQL detections.");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "postgresql/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "tcp", "smb-login", "ssh-login" ) ) {

  install_list = get_kb_list( "postgresql/" + source + "/*/installs" );

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
    os_arch  = infos[4];

    cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:postgresql:postgresql:" );
    if( ! cpe )
      cpe = "cpe:/a:postgresql:postgresql";

    # nb: As remote VTs requires a 'postgresql' service
    if( source == "tcp" )
      source = "postgresql";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';
    report += build_detection_report( app:"PostgreSQL",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concluded:concl );

  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );