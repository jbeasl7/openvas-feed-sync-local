# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125295");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-02 09:10:43 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Elastic Logstash Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Elastic Logstash detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_elastic_logstash_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_elastic_logstash_smb_login_detect.nasl");
  script_mandatory_keys("elastic/logstash/detected");

  script_xref(name:"URL", value:"https://www.elastic.co/");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "elastic/logstash/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list("smb-login", "http" ) ) {

  install_list = get_kb_list( "elastic/logstash/" + source + "/*/installs" );
  if( ! install_list )
    continue;

  install_list = sort( install_list );

  foreach install( install_list ) {
    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port      = infos[0];
    install   = infos[1];
    version   = infos[2];
    concl     = infos[3];
    concl_url = infos[4];

    cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:elastic:logstash:" );
    cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:elasticsearch:logstash:" );
    if( ! cpe1 ) {
      cpe1 = "cpe:/a:elastic:logstash";
      cpe2 = "cpe:/a:elasticsearch:logstash";
    }

    if( source == "http" )
      source = "www";

    register_product( cpe:cpe1, location:install, port:port, service:source );
    register_product( cpe:cpe2, location:install, port:port, service:source );

    if( report )
      report += '\n\n';

    report += build_detection_report( app:"Elastic Logstash",
                                      version:version,
                                      install:install,
                                      cpe:cpe1,
                                      concludedUrl:concl_url,
                                      concluded:concl );
  }
}

log_message( port:0, data:chomp( report ) );

exit( 0 );
