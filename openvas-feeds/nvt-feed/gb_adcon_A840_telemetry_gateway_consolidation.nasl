# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105490");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-09-10T05:38:24+0000");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-12-17 16:20:27 +0100 (Thu, 17 Dec 2015)");
  script_name("Adcon A840 Telemetry Gateway Consolidation");

  script_tag(name:"summary", value:"Consolidation of Adcon A840 Telemetry Gateway detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_adcon_A840_telemetry_gateway_http_detect.nasl",
                      "gb_adcon_A840_telemetry_gateway_telnet_detect.nasl");
  script_mandatory_keys("adcon/telemetry_gateway_a840/detected");
  exit(0);
}

include("host_details.inc");

cpe = "cpe:/a:adcon:telemetry_gateway_a840";
source = "telnet";
vers = "unknown";

if( ! version = get_kb_item( "tg_A840/telnet/version" ) ) {
  source = "HTTP";
  version = get_kb_item( "tg_A840/http/version" );
}

if( version ) {
  vers = version;
  cpe += ":" + vers;
}

register_product( cpe:cpe, location:source );

log_message( data:build_detection_report( app:"Adcon A840 Telemetry Gateway",
                                          version:vers,
                                          install:source,
                                          cpe:cpe,
                                          concluded:source ),
             port:0 );

exit( 0 );
