# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125178");
  script_version("2025-04-01T05:39:41+0000");
  script_tag(name:"last_modification", value:"2025-04-01 05:39:41 +0000 (Tue, 01 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-03-21 09:31:06 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Wicket Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Apache Wicket detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_apache_wicket_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_apache_wicket_smb_login_detect.nasl",
                        "gsf/gb_apache_wicket_ssh_login_detect.nasl");
  script_mandatory_keys("apache/wicket/detected");

  script_xref(name:"URL", value:"https://wicket.apache.org/");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "apache/wicket/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "http", "smb-login", "ssh-login" ) ) {

  install_list = get_kb_list( "apache/wicket/" + source + "/*/installs" );
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
    extra    = infos[5];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:wicket:" );
    if( ! cpe )
      cpe = "cpe:/a:apache:wicket";

    if( source == "http" )
      source = "www";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';

    report += build_detection_report( app:"Apache Wicket",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      extra:extra,
                                      concludedUrl:conclurl,
                                      concluded:concl );
  }
}

log_message( port:0, data:chomp( report ) );

exit( 0 );
