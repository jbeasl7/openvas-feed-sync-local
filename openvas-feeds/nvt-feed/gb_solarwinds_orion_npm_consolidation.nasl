# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142006");
  script_version("2024-08-01T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-01 05:05:42 +0000 (Thu, 01 Aug 2024)");
  script_tag(name:"creation_date", value:"2019-02-19 10:04:35 +0700 (Tue, 19 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SolarWinds Orion Network Performance Monitor (NPM) Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of SolarWinds Orion Network Performance Monitor
  (NPM) detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_solarwinds_orion_npm_http_detect.nasl", "gb_solarwinds_orion_npm_smb_login_detect.nasl");
  script_mandatory_keys("solarwinds/orion/npm/detected");

  script_xref(name:"URL", value:"http://www.solarwinds.com/products/orion/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "solarwinds/orion/npm/detected" ) )
  exit( 0 );

detected_version = "unknown";

foreach source( make_list( "smb", "http" ) ) {
  version_list = get_kb_list( "solarwinds/orion/npm/" + source + "/*/version" );
  foreach vers( version_list ) {
    if( vers != "unknown" && detected_version == "unknown" ) {
      detected_version = vers;
      break;
    }
  }
}

# e.g. 9.5 SP2
cpe_vers = str_replace( string:detected_version, find:" ", replace:"." );
cpe_vers = tolower( cpe_vers );
cpe = build_cpe( value:cpe_vers, exp:"^([0-9SP. ]+)", base:"cpe:/a:solarwinds:orion_network_performance_monitor:" );
if( ! cpe )
  cpe = "cpe:/a:solarwinds:orion_network_performance_monitor";

if( http_ports = get_kb_list( "solarwinds/orion/npm/http/port" ) ) {
  foreach port( http_ports ) {

    extra += 'Remote Detection over HTTP(s):\n';
    extra += '  HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item( "solarwinds/orion/npm/http/" + port + "/concluded" );
    if( concluded )
      extra += '    Concluded from:  ' + concluded + '\n';

    location =  get_kb_item( "solarwinds/orion/npm/http/" + port + "/location" );
    if( location )
      extra += '    Location:        ' + location + '\n';

    register_product( cpe:cpe, location:location, port:port, service:"www" );
  }
}

if( win_path = get_kb_item( "solarwinds/orion/npm/smb/path" ) ) {
  extra += 'Local Detection on Windows:\n';
  extra += 'Path:           ' + win_path + '\n';

  if( concluded = get_kb_item( "solarwinds/orion/npm/smb/concluded" ) )
    extra += concluded + '\n';

  register_product( cpe:cpe, location:win_path, port:0, service:"smb-login" );
}
display_name = get_kb_item( "solarwinds/orion/npm/smb/display_name" );
os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows",
                        desc:display_name + " Detection Consolidation", runs_key:"windows" );

report = build_detection_report( app:display_name, version:detected_version, cpe:cpe, install:"/" );

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port:0, data:report );

exit( 0 );
