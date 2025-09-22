# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812377");
  script_version("2025-06-27T05:41:33+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-06-27 05:41:33 +0000 (Fri, 27 Jun 2025)");
  script_tag(name:"creation_date", value:"2018-01-03 16:00:40 +0530 (Wed, 03 Jan 2018)");
  script_name("D-Link DSL Devices Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("d-link/dsl/banner");

  script_tag(name:"summary", value:"HTTP based detection of D-Link DSL Devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

# Important: If changing / extending the response / banner check pattern below please make sure to
# handle the relevant check / handling in gb_get_http_banner.nasl accordingly.

foreach url( make_list( "/", "/cgi-bin/webproc" ) ) {

  buf = http_get_cache( port:port, item:url );
  # Server: Linux, WEBACCESS/1.0, DSL-2890AL Ver AU_1.02.10
  # Server: uhttpd
  if( ! egrep( string:buf, pattern:"^Server\s*:\s*(Boa|micro_httpd|Linux|RomPager|uhttpd)", icase:TRUE ) &&
      "/cgi-bin/SETUP/sp_home.asp" >!< buf && "/page/login/login.html" >!< buf &&"<title>VDSL Router</title>" >!< buf )
    continue;

  # Seen on DSL-2888A
  if( buf =~ "Location\s*:\s*/page/login/login\.html" )
    buf = http_get_cache( port:port, item:"/page/login/login.html" );

  # NOTE: Those are NO D-Link but Asus Routers:
  # WWW-Authenticate: Basic realm="DSL-N10"
  # WWW-Authenticate: Basic realm="DSL-N14U"
  # They have a separate "Server: httpd" banner which is skipped above.
  #
  # NOTE2: There are also a few with the following out:
  # WWW-Authenticate: Basic realm="DSL Router"
  # Server: micro_httpd
  # Those are very unlikely D-Link devices...

  # <div class="pp">Product Page : DSL-2890AL<a href="javascript:check_is_modified('http://support.dlink.com/')"><span id="model" align="left"></span></a></div>
  # <span class="product">Product Page : <a href="http://support.dlink.com" target="_blank">DSL-2890AL</a></span>
  if( buf =~ 'WWW-Authenticate\\s*:\\s*Basic realm="DSL-([0-9A-Z]+)' || "<title>D-Link DSL-" >< buf ||
      ( "D-Link" >< buf && ( buf =~ "Product Page\s*:\s*(<[^>]+>)?DSL\-" || buf =~ "Server\s*:\s*Linux, WEBACCESS/1\.0, DSL-" ) ) ||
      ( "DSL Router" >< buf && buf =~ "Copyright.*D-Link Systems" ) ||
      ( "<TITLE>DSL-" >< buf && "var PingDlink" >< buf ) ||
      ( 'var Manufacturer="D-Link"' >< buf && 'var ModelName="DSL-' >< buf ) ) {
    fw_conclurl   = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    fw_version = "unknown";
    hw_version = "unknown";
    model      = "unknown";
    install    = "/";

    # For DSL-2888A which differs from others (again)
    # var ModelName="DSL-2888A";
    mo = eregmatch( pattern:'(Product Page ?: ?|var ModelName="|Server: Linux, (HTTP|STUNNEL|WEBACCESS)/1\\.0, |Basic realm=")?DSL-([0-9A-Z]+)', string:buf );
    if( mo[3] ) {
      model    = mo[3];
      fw_concluded = mo[0];
      set_kb_item( name:"d-link/dsl/http/" + port + "/model", value:model );
    }

    # <div class="fwv">Firmware Version : AU_1.02.06<span id="fw_ver" align="left"></span></div>
    # var SoftwareVersio="AU_2.00";
    # var SoftwareVersio="AU_2.12";
    # var SoftwareVersio="AU_2.31";
    # var SoftwareVersio="EG_1.00b4";
    # var SoftwareVersio="ME_1.01";
    # nb: the missing "n" in "SoftwareVersio" was seen like this. It is unclear if this is a
    # bug in some specific firmware version (HardwareVersion is using the "n") so we're checking
    # both in this regex:
    fw_ver = eregmatch( pattern:'(Firmware Version ?: |var SoftwareVersion?=")([A-Z]+_|V)?([0-9.]+)', string:buf );
    if( fw_ver[3] ) {
      fw_version = fw_ver[3];
      set_kb_item( name:"d-link/dsl/http/" + port + "/fw_version", value:fw_version );
      if( fw_concluded )
        fw_concluded += '\n    ';
      fw_concluded += fw_ver[0];
    }

    if( fw_version == "unknown" ) {
      # nb: Not available on all DSL- devices
      url2   = "/ayefeaturesconvert.js";
      req    = http_get( port:port, item:url2 );
      res    = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
      fw_ver = eregmatch( string:res, pattern:'var AYECOM_FWVER="([0-9]\\.[0-9]+)";' );
      if( fw_ver[1] ) {
        fw_version = fw_ver[1];
        set_kb_item( name:"d-link/dsl/http/" + port + "/fw_version", value:fw_version );
        if( fw_conclurl )
          fw_conclurl += '\n    ';
        fw_conclurl += http_report_vuln_url( port:port, url:url2, url_only:TRUE );
        if( fw_concluded )
          fw_concluded += '\n    ';
        fw_concluded += fw_ver[0];
      }
    }

    if( fw_version == "unknown" ) {
      # e.g. on DSL-2875AL
      # var showfwver='1.00.01';
      url2 = "/cgi-bin/login.asp";
      res = http_get_cache( port:port, item:url2 );
      fw_ver = eregmatch( pattern:"var showfwver='([0-9.]+)'", string:res );
      if( ! isnull( fw_ver[1] ) ) {
        fw_version = fw_ver[1];
        set_kb_item( name:"d-link/dsl/http/" + port + "/fw_version", value:fw_version );
        if( fw_conclurl )
          fw_conclurl += '\n    ';
        fw_conclurl += http_report_vuln_url( port:port, url:url2, url_only:TRUE );
        if( fw_concluded )
          fw_concluded += '\n    ';
        fw_concluded += fw_ver[0];
      }
    }

    # <div class="hwv">Hardware Version : A1<span id="hw_ver" align="left"></span></div>
    # var HardwareVersion="T1";
    # nb: See note on "SoftwareVersio" above.
    hw_ver = eregmatch( pattern:'(>Hardware Version ?: |var HardwareVersion?=")([0-9A-Za-z.]+)', string:buf );
    if( hw_ver[2] ) {
      hw_version = hw_ver[2];
      hw_cpe    += ":" + tolower( hw_version );
      set_kb_item( name:"d-link/dsl/http/" + port + "/hw_version", value:hw_version );
      hw_concluded += hw_ver[0];
      hw_conclurl   = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    # nb: The new key for D-Link active checks affecting multiple device types
    set_kb_item( name:"d-link/http/detected", value:TRUE );

    set_kb_item( name:"d-link/dsl/detected", value:TRUE );
    set_kb_item( name:"d-link/dsl/http/detected", value:TRUE );
    set_kb_item( name:"d-link/dsl/http/port", value:port );

    if( fw_concluded )
      set_kb_item( name:"d-link/dsl/http/" + port + "/fw_concluded", value:fw_concluded );

    if( fw_conclurl )
      set_kb_item( name:"d-link/dsl/http/" + port + "/fw_conclurl", value:fw_conclurl );

    if( hw_concluded )
      set_kb_item( name:"d-link/dsl/http/" + port + "/hw_concluded", value:hw_concluded );

    if( hw_conclurl )
      set_kb_item( name:"d-link/dsl/http/" + port + "/hw_conclurl", value:hw_conclurl );

    exit( 0 );
  }
}

exit( 0 );
