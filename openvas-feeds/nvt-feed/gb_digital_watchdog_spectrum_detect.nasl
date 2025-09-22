# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113237");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-25 12:00:00 +0200 (Wed, 25 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Digital Watchdog Spectrum Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 7001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Digital Watchdog Products.");

  script_tag(name:"insight", value:"All Digital Watchdog Products come with the 'Spectrum' software.");

  script_xref(name:"URL", value:"https://digital-watchdog.com/");

  exit(0);
}

CPE = "cpe:/h:digital_watchdog:spectrum:";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");

port = http_get_port( default: 7001 );

foreach dir ( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {
  location = dir;
  if( location == "/" )
    location = "";

  location = location + "/static/index.html";

  buf = http_get_cache( item: location, port: port );
  if( buf !~ '[Ss]erver: [Dd][Ww][ ]?[Ss]pectrum' && buf !~ '[Ss]erver:[^\r\n]*[Dd]igital [Ww]atch[Dd]og' )
    continue;

  conclUrl = http_report_vuln_url( port: port, url: location, url_only: TRUE );

  set_kb_item( name: "digital_watchdog/detected", value: TRUE );
  set_kb_item( name: "digital_watchdog/http/port", value: port );

  version = "unknown";
  vers = eregmatch( string: buf, pattern: '[Ss]erver: [Dd][Ww][ ]?[Ss]pectrum/([0-9.]+)' );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name: "digital_watchdog/version", value: version );
  }

  register_and_report_cpe( app: "Digital Watchdog Spectrum",
                           ver: version,
                           concluded: vers[0],
                           base: CPE,
                           expr: "([0-9.]+)",
                           insloc: dir,
                           regPort: port,
                           conclUrl: conclUrl );
}

exit( 0 );
