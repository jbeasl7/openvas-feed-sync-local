# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106015");
  script_version("2025-06-17T05:40:22+0000");
  script_tag(name:"last_modification", value:"2025-06-17 05:40:22 +0000 (Tue, 17 Jun 2025)");
  script_tag(name:"creation_date", value:"2015-07-10 14:32:27 +0700 (Fri, 10 Jul 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("D-Link DNS NAS Devices Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("d-link/dns/banner");

  script_tag(name:"summary", value:"HTTP based detection of D-Link DNS NAS devices.");

  script_xref(name:"URL", value:"https://www.dlink.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

fw_version = "unknown";
os_app     = "D-Link DNS";
os_cpe     = "cpe:/o:dlink:dns";
hw_version = "unknown";
hw_app     = "D-Link DNS";
hw_cpe     = "cpe:/h:dlink:dns";
model      = "unknown";
install    = "/";

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

# Important: If changing / extending the response / banner check pattern below please make sure to
# handle the relevant check / handling in gb_get_http_banner.nasl accordingly.

# DNS-320, DNS-320L, DNS-325, DNS-327L, DNS-345
# nb: We might want to reconsider this as the banner might be not always there...
if( egrep( string:banner, pattern:"^Server\s*:\s*lighttpd/", icase:TRUE ) ) {

  res = http_get_cache( item:"/", port:port );
  if( ! res ) exit( 0 );

  # "ShareCenter by D-Link" Logo on e.g. DNS-325, previous versions of this Detection-VT has
  # only checked for a "ShareCenter" string which might not be there on different firmware versions.
  logo_identified = FALSE;
  logo_url = "/web/images/logo.png";
  if( logo_url >< res ) {
    req  = http_get( item:logo_url, port:port );
    res2 = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    if( res2 && hexstr( MD5( res2 ) ) == "0b5e6b0092c45768fbca24706bc9e08d" )
      logo_identified = TRUE;
  }

  if( "Please Select Your Account" >< res && ( "ShareCenter" >< res || logo_identified ) ) {

    found = TRUE;

    url = "/xml/info.xml";
    res = http_get_cache( item:url, port:port );

    # nb: Some devices (DNS-320L with firmware 1.08 was such a case) are responding with
    # a 404 on /xml/info.xml but provided the required info on //xml/info.xml.
    if( !res || res !~ "<info>" || res !~ "www\.dlink\.com" ) {
      url = "//xml/info.xml";
      res = http_get_cache( item:url, port:port );
    }

    if( res =~ "<info>" && res =~ "www\.dlink\.com" ) {

      # <hw_ver>DNS-325</hw_ver>
      # <hw_ver>DNS-320L</hw_ver>
      # <hw_ver>DNS-320LW</hw_ver>
      mo = eregmatch( pattern:"<hw_ver>DNS-(.*)</hw_ver>", string:res );
      if( mo[1] ) {
        model = mo[1];
        concluded = mo[0];
        os_app += "-" + model + " Firmware";
        os_cpe += "-" + tolower( model ) + "_firmware";
        hw_app += "-" + model + " Device";
        hw_cpe += "-" + tolower( model );
        set_kb_item( name:"d-link/dns/model", value:model );
      } else {
        os_app += " Unknown Model Firmware";
        os_cpe += "-unknown_model_firmware";
        hw_app += " Unknown Model Device";
        hw_cpe += "-unknown_model";
      }

      # <version>1.00</version>
      # <version>1.08</version>
      fw_ver = eregmatch( pattern:"<version>(.*)</version>", string:res );
      if( fw_ver[1] ) {
        os_cpe    += ":" + fw_ver[1];
        fw_version = fw_ver[1];
        set_kb_item( name:"d-link/dns/fw_version", value:fw_version );
        if( concluded )
          concluded += '\n';
        concluded += fw_ver[0];
      }
      if( fw_version != "unknown" || model != "unknown" )
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    url = "/cgi-bin/info.cgi";

    res = http_get_cache( port:port, item:url );

    # Product=nas
    # Model=DNS-320B
    # Version=1.03.0322.2019
    # Build=
    # Macaddr=D1:F1:E1:51:61:41
    # Wireless=NO
    # Ptz=

    if( model == "unknown" ) {
      mo = eregmatch( pattern:"Model\s*=\s*(DNS-[0-9A-Z]+)", string: res);
      if( ! isnull( mo[1] ) ) {
        model = mo[1];
        if( concluded )
          concluded += '\n';
        concluded += mo[0];
        os_app += "-" + model + " Firmware";
        os_cpe += "-" + tolower( model ) + "_firmware";
        hw_app += "-" + model + " Device";
        hw_cpe += "-" + tolower( model );
        set_kb_item( name:"d-link/dns/model", value:model );
      }
    }

    if( fw_version == "unknown" ) {
      fw_ver = eregmatch( pattern:"Version\s*=\s*([0-9.]+)", string:res );
      if( ! isnull( fw_ver[1] ) ) {
        os_cpe += ":" + fw_ver[1];
        fw_version = fw_ver[1];
        if( concluded )
          concluded += '\n';
        concluded = fw_ver[0];
        conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    mac = eregmatch( pattern:"Macaddr\s*=\s*([0-9A-F:]{17})", string:res );
    if( ! isnull( mac[1] ) ) {
      register_host_detail( name:"MAC", value:mac[1], desc:"D-Link DNS NAS Devices Detection (HTTP)" );
      replace_kb_item( name:"Host/mac_address", value:mac[1] );
      extra = "MAC address: " + mac[1];
    }

    if( model == "unknown" ) {
      os_app += " Unknown Model Firmware";
      os_cpe += "-unknown_model_firmware";
      hw_app += " Unknown Model Device";
      hw_cpe += "-unknown_model";
    }
  }
}

# TODO: At least the check here seems to be quite unreliable, this should be updated if possible...
# DNS-321, DNS-323, DNS-343
else if( egrep( string:banner, pattern:"^Server\s*:\s*GoAhead-Webs", icase:TRUE ) ) {

  res = http_get_cache( item:"/web/login.asp", port:port );

  if( egrep( string:res, pattern:"<TITLE>dlink(.*)?</TITLE>", icase:TRUE ) && "D-Link Corporation/D-Link Systems, Inc." >< res ) {
    found = TRUE;
    os_app += " Unknown Model Firmware";
    os_cpe += "-unknown_model_firmware";
    hw_app += " Unknown Model Device";
    os_cpe += "-unknown_model";
  }
}

if( found ) {

  set_kb_item( name:"d-link/http/detected", value:TRUE );
  set_kb_item( name:"d-link/detected", value:TRUE );
  set_kb_item( name:"d-link/dns/detected", value:TRUE );
  set_kb_item( name:"d-link/dns/http/detected", value:TRUE );

  os_register_and_report( os:os_app, cpe:os_cpe, banner_type:"D-Link DNS Device Login Page", port:port,
                          desc:"D-Link DNS Devices Detection", runs_key:"unixoide" );
  register_product( cpe:os_cpe, location:install, port:port, service:"www" );
  register_product( cpe:hw_cpe, location:install, port:port, service:"www" );

  report = build_detection_report( app:os_app, version:fw_version, concludedUrl:conclUrl,
                                   concluded:concluded, install:install, cpe:os_cpe, extra:extra );

  report += '\n\n' + build_detection_report( app:hw_app, skip_version:TRUE, install:install, cpe:hw_cpe );

  log_message( port:port, data:report );
}

exit( 0 );
