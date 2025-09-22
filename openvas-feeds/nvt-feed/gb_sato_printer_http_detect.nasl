# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112773");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-06-30 13:22:14 +0000 (Tue, 30 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SATO Printer Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of SATO printers.");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = http_get_port( default: 443 );

url = "/WebConfig/";
buf = http_get_cache( port: port, item: url );

if( buf && buf =~ "^HTTP/1\.[01] 200" && "<title>SATO Printer Setup</title>" >< buf ) {

    set_kb_item( name: "sato_printer/detected", value: TRUE );
    set_kb_item( name: "sato_printer/http/detected", value: TRUE );
    set_kb_item( name: "sato_printer/http/port", value: port );

    url = "/rest/info";
    buf = http_get_cache( item: url, port: port );

    if( buf && "printCount" >< buf && "model" >< buf ) {

      # "model":"CL6NX-J 203dpi"
      mod = eregmatch( pattern: '"model":"([^"]+)",', string: buf );
      if( ! isnull( mod[1] ) ) {
        set_kb_item( name: "sato_printer/http/" + port + "/model", value: mod[1] );
      }

      # nb: The dashboard shows it as e.g.: Firmware version: 1.9.4-r2
      # However the info is available via the REST api call like e.g.:
      # version":"1.9.4-r2"
      # version":"6.1.0-u419_r2"
      # nb: Note that the REST JSON response contains multiple versions
      # so the regex below is trying to get the correct by assuming it
      # is located after the system part.
      vers = eregmatch( pattern: '"system":.+"version":"([^"]+)"', string: buf );
      if( ! isnull( vers[1] ) ) {
        set_kb_item( name: "sato_printer/http/" + port + "/fw_version", value: vers[1] );
        set_kb_item( name: "sato_printer/http/" + port + "/concluded", value: vers[0] );
        set_kb_item( name: "sato_printer/http/" + port + "/concludedUrl",
                     value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
      }

      # "MAC":"00:19:98:16:3E:FD"
      mac = eregmatch( pattern: '"MAC":"([^"]+)"', string: buf );
      if( ! isnull( mac[1] ) ) {
        mac = tolower( mac[1] );
        set_kb_item( name: "sato_printer/http/" + port + "/mac", value: mac );
        register_host_detail( name: "MAC", value: mac, desc: "gb_sato_printer_http_detect.nasl" );
        replace_kb_item( name: "Host/mac_address", value: mac );
      }

      exit( 0 );
    }
  }

exit( 0 );
