# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102097");
  script_version("2024-06-21T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-04-18 08:09:53 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Microsoft SQL (MSSQL) Server Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_microsoft_sql_server_tcp_ip_listener_detect.nasl",
                      "gb_microsoft_sql_server_smb_login_detect.nasl");
  script_mandatory_keys("microsoft/sqlserver/detected");

  script_tag(name:"summary", value:"Consolidation of Microsoft SQL (MSSQL) Server detections.");

  script_tag(name:"insight", value:"Note: Using only the remote detection capabilities will yield
  unreliable results, due to insuffiecient exposed version information.");

  script_xref(name:"URL", value:"https://www.microsoft.com/sql-server");

  exit(0);
}

include("host_details.inc");
include("mssql.inc");

if( ! get_kb_item( "microsoft/sqlserver/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "smb-login", "tcp_listener" ) ) {

  install_list = get_kb_list( "microsoft/sqlserver/" + source + "/*/installs" );

  if( ! install_list )
    continue;

  install_list = sort( install_list );

  foreach install( install_list ) {

    cpe = "cpe:/a:microsoft:sql_server";
    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 4 )
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    app      = infos[1];
    install  = infos[2];
    version  = infos[3];
    concl    = infos[4];
    conclurl = infos[5];

    releaseName = mssql_get_rel_name( version:version );
    if( releaseName != "unknown release name" ) {
      cpe_rel = tolower( releaseName );
      cpe_rel = str_replace( string:cpe_rel, find:" ", replace:":" );
      cpe += ":" + cpe_rel;
    }

    if( version != "unknown" )
      register_product( cpe:cpe, location:install, port:port, service:source, internal_version:version );
    else
      register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';

    if( app == "unknown" )
      app = "Microsoft SQL (MSSQL) Server " + releaseName;

    report += build_detection_report( app:app,
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concluded:concl );
  }
}

log_message( port:0, data:chomp( report ) );

exit( 0 );
