# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112771");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2020-06-16 12:05:00 +0000 (Tue, 16 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DSX Communication Devices Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of DSX communication devices.

  Note: Providing login credentials allows to extract detailed device information.");

  script_add_preference(name:"DSX User Name", value:"", type:"entry", id:1);
  script_add_preference(name:"DSX Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://www.dsxinc.com/modules.htm");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );

#nb: Check the md5sum of the vendor's logo where no other info is available to prevent FPs
img_fingerprint = "d31186196513fa17f7455f101a3b437b";
img_url = "/netburner-logo.gif";
img_found = FALSE;

img_req = http_get( port:port, item: img_url );
img_res = http_keepalive_send_recv( port:port, data:img_req, bodyonly:TRUE );

if( ! isnull( img_res ) ) {
  img_md5 = hexstr( MD5( img_res ) );
  if( img_fingerprint == img_md5 ) {
    img_found = TRUE;
  }
}

#nb: Setting this to /INDEX.HTM will prevent a redirect and also provide the HTTP header information needed later
res = http_get_cache( port:port, item:"/INDEX.HTM" );

# nb: Some systems had two spaces in front of the "401".
if( res =~ "^HTTP/1\.[01]  ?401" && ( "<strong>DSX Access Systems, Inc.</strong>" >< res || ( img_found && "<H1>Your Authentication failed<BR></H1>" >< res ) ) ) {

  set_kb_item( name:"dsx/communication_device/detected", value:TRUE );

  hw_name = "DSX Communication Device";
  os_name = "DSX Communication Device Firmware";
  hw_cpe = "cpe:/h:dsx:communication_device";
  os_cpe = "cpe:/o:dsx:communication_device_firmware";
  version = "unknown";
  model_detected = FALSE;
  location = "/";

  user = script_get_preference( "DSX User Name" );
  pass = script_get_preference( "DSX Password" );

  if( ! user && ! pass ) {
    extra = "DSX communication device detected but specific device and version information unknown. Providing login credentials to this VT might allow to gather more reliable results.";
  } else if( ! user && pass ) {
    log_message( port:port, data:"Password provided but User Name is missing." );
  } else if( user && ! pass ) {
    log_message( port:port, data:"User Name provided but Password is missing." );
  } else if( user && pass ) {

    #nb: Depending on the type of networking device, we need different URLs. They shouldn't overlap.
    foreach url( make_list( "/INDEX.HTM", "/devicedetails.ssi" ) ) {
      add_headers = make_array( "Authorization", "Basic " + base64( str:user + ":" + pass ) );

      req = http_get_req( port:port, url:url, add_headers:add_headers );
      res = http_keepalive_send_recv( port:port, data:req );

      # See note about the additional space above.
      if( res =~ "^HTTP/1\.[01]  ?200" && "DSX" >< res && "Firmware Version" >< res ) {
        # Firmware Version: DSX-LAN-D v4.14 AUG 21 2019;0;9600"
        # Firmware Version: LANMOD v1.09 Sep 30 2016
        vers = eregmatch( string:res, pattern:"Firmware Version: ((DSX-)?[^ ]+) v([0-9.]+)" );

        if( ! isnull( vers[1] ) && ! model_detected ) {

          model_detected = TRUE;
          model = vers[1];

          if( model !~ "^DSX-" )
            model = "DSX-" + model;

          hw_name = model + " Communication Device";
          os_name = hw_name + " Firmware";
          hw_cpe = "cpe:/h:dsx:" + tolower( model );
          os_cpe = "cpe:/o:dsx:" + tolower( model ) + "_firmware";
        }

        if( ! isnull( vers[3] ) ) {
          version = vers[3];
          os_cpe += ":" + version;
          concl = vers[0];
          conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      } else {
        log_message( port:port, data:'User Name and Password provided but login failed on ' + url + ' with the following response:\n\n' + res );
      }
    }
  }

  # nb: Trying to fetch the model without any provided credentials.
  # The content of "Basic realm" is not always related to the DSX device.
  # WWW-Authenticate: Basic realm= LAN-D => DSX device
  # WWW-Authenticate: Basic realm="SBL2E" => 3rd party Serial to Ethernet device
  if( ! model_detected ) {
    model_match = eregmatch( pattern:'WWW-Authenticate: Basic realm=\\s*"?([^\n\r"]+)', string:res, icase:TRUE );
    if( ! isnull( model_match[1] ) && "LAN-D" >< model_match[1] ) {

      model_detected = TRUE;
      model = model_match[1];

      if( model !~ "^DSX-" )
        model = "DSX-" + model;

      hw_name = model + " Communication Device";
      os_name = hw_name + " Firmware";
      hw_cpe = "cpe:/h:dsx:" + tolower( model );
      os_cpe = "cpe:/o:dsx:" + tolower( model ) + "_firmware";
      concl = model_match[0];
    }
  }

  os_register_and_report( os:os_name, cpe:os_cpe, desc:"DSX Communication Devices Detection (HTTP)", runs_key:"unixoide" );

  register_product( cpe:os_cpe, location:location, port:port, service:"www" );
  register_product( cpe:hw_cpe, location:location, port:port, service:"www" );

  report = build_detection_report( app:os_name, version:version, install:location, cpe:os_cpe );
  report += '\n\n';
  report += build_detection_report( app:hw_name, skip_version:TRUE, install:location, cpe:hw_cpe );

  if( concl ) {
    report += '\n\nConcluded from version/product identification result:';
    report += '\n' + concl;
    if( conclUrl ) {
      report += '\n\nConcluded from version/product identification location:';
      report += '\n' + conclUrl;
    }
  }

  if( extra ) {
    report += '\n\nExtra information:';
    report += '\n' + extra;
  }

  log_message( port:port, data:report );
}

exit( 0 );
