# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103908");
  script_version("2023-03-15T10:19:45+0000");
  script_tag(name:"last_modification", value:"2023-03-15 10:19:45 +0000 (Wed, 15 Mar 2023)");
  script_tag(name:"creation_date", value:"2014-02-18 11:22:35 +0100 (Tue, 18 Feb 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Home Network Administration Protocol (HNAP) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to determine if the Home Network Administration Protocol (HNAP) is supported.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_keepalive.inc");
include("misc_func.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );

# nb: All devices using the POST forms contain this redirection; thus only trying to optimize and prevent unnecessary requests
url = "/";
res = http_get_cache( item:url, port:port );

if ( res && res =~ "/Login.html" ) {
  url = "/HNAP1/";

  data = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' +
         ' xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
         '<soap:Body><GetDeviceSettings xmlns="http://purenetworks.com/HNAP1/" /></soap:Body></soap:Envelope>';

  header = make_array( "Accept-Encoding", "gzip, deflate",
                       "X-Requested-With", "XMLHttpRequest",
                       "Content-Type", "text/xml; charset=UTF-8",
                       "Soapaction", '"http://purenetworks.com/HNAP1/GetDeviceSettings"' );
  # nb: We send the POST first as there are devices that reply to GET requests also, but with bogus data
  req = http_post_put_req( port:port, url:url, data:data, add_headers:header );
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( ! buf || "soap:Envelope" >!< buf || "SOAPActions" >!< buf || "http://purenetworks.com/HNAP1" >!< buf ) {
    # nb: This exists only for D-Link Rxx series, and while the request is not proper HNAP, the response data is identical with HNAP one
    url = "/DHMAPI/";

    data = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' +
     ' xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
     "<soap:Body><GetDeviceSettings/></soap:Body></soap:Envelope>";

    header = make_array( "Accept-Encoding", "gzip, deflate",
                         "X-Requested-With", "XMLHttpRequest",
                         "Content-Type", "text/xml; charset=UTF-8",
                         "API-ACTION", "GetDeviceSettings" );

    req = http_post_put_req( port:port, url:url, data:data, add_headers:header );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
  }
}
if( ! buf || "soap:Envelope" >!< buf || "SOAPActions" >!< buf ) {
  url = "/HNAP1";
  req = http_get( item:url, port:port );

  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
  # nb: e.g. on a D-Link DIR-868L the URL needs a trailing "/"
  if( ! buf || "soap:Envelope" >!< buf || "SOAPActions" >!< buf || "http://purenetworks.com/HNAP1" >!< buf ) {
    url = "/HNAP1/";
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
  }
}

if( buf && "soap:Envelope" >< buf && "SOAPActions" >< buf ) {

  # e.g. <VendorName>D-Link</VendorName>
  if( "<VendorName>" >< buf ) {
    vendor = eregmatch( pattern:"<VendorName>([^<]+)</VendorName>", string:buf );
    if( ! isnull( vendor[1] ) ) {
      set_kb_item( name:"HNAP/" + port + "/vendor", value:vendor[1] );
      set_kb_item( name:"HNAP/" + port + "/vendor_concluded", value:vendor[0] );
      set_kb_item( name:"HNAP/vendor", value:TRUE );
      report += '\nVendor:   ' + vendor[1];
    }
  }

  # e.g.
  # <ModelName>DIR-868L</ModelName>
  # <ModelName>"DIR-825"</ModelName>
  if( "<ModelName>" >< buf ) {
    model = eregmatch( pattern:'<ModelName>"?([^<"]+)"?</ModelName>', string:buf );
    if( ! isnull( model[1] ) ) {
      set_kb_item( name:"HNAP/" + port + "/model", value:model[1] );
      set_kb_item( name:"HNAP/" + port + "/model_concluded", value:model[0] );
      set_kb_item( name:"HNAP/model", value:TRUE );
      report += '\nModel:    ' + model[1];
    }
  }

  # e.g.
  # <DeviceName>D-Link Systems DIR-615</DeviceName>
  # <DeviceName>D-Link Systems DIR-825</DeviceName>
  if( "<DeviceName>" >< buf ) {
    device_name = eregmatch( pattern:'<DeviceName>"?([^<"]+)"?</DeviceName>', string:buf );
    if( ! isnull( device_name[1] ) ) {
      set_kb_item( name:"HNAP/" + port + "/devicename", value:device_name[1] );
      set_kb_item( name:"HNAP/" + port + "/devicename_concluded", value:device_name[0] );
      report += '\nDevice:   ' + device_name[1];
    }
  }

  # e.g.
  # <FirmwareVersion>2.03</FirmwareVersion>
  # <FirmwareVersion>1.20, Tue 28 Nov 2017</FirmwareVersion>
  if( "<FirmwareVersion>" >< buf ) {
    fw = eregmatch( pattern:"<FirmwareVersion>([^<,]+),?[^<]*</FirmwareVersion>", string:buf );
    if( ! isnull( fw[1] ) ) {
      set_kb_item( name:"HNAP/" + port + "/firmware", value:fw[1] );
      set_kb_item( name:"HNAP/" + port + "/firmware_concluded", value:fw[0] );
      set_kb_item( name:"HNAP/firmware", value:TRUE );
      report += '\nFirmware: ' + fw[1];
    }
  }

  # e.g. <HardwareVersion>B1</HardwareVersion>
  if( "<HardwareVersion>" >< buf ) {
    hw = eregmatch( pattern:"<HardwareVersion>([^<]+)</HardwareVersion>", string:buf );
    if( ! isnull( hw[1] ) ) {
      set_kb_item( name:"HNAP/" + port + "/hardware", value:hw[1] );
      set_kb_item( name:"HNAP/" + port + "/hardware_concluded", value:hw[0] );
      set_kb_item( name:"HNAP/hardware", value:TRUE );
      report += '\nHardware: ' + hw[1];
    }
  }

  # nb: in rare cases, Vendor is missing so we can use this also for detection
  # e.g. <PresentationURL>https://dlinkrouter.local/</PresentationURL>
  if( "<PresentationURL>" >< buf ) {
    presentation = eregmatch( pattern:"<PresentationURL>([^<]+)</PresentationURL>", string:buf );
    if( ! isnull( presentation[1] ) ) {
      set_kb_item( name:"HNAP/" + port + "/presentationurl", value:presentation[1] );
      set_kb_item( name:"HNAP/" + port + "/presentationurl_concluded", value:presentation[0] );
      report += '\nURL:      ' + presentation[1];
    }
  }

  conclUrl = http_report_vuln_url( url:url, port:port, url_only:TRUE );

  set_kb_item( name:"HNAP/port", value:port );
  set_kb_item( name:"HNAP/" + port + "/detected", value:TRUE );
  set_kb_item( name:"HNAP/" + port + "/location", value:url );
  set_kb_item( name:"HNAP/" + port + "/conclurl", value:conclUrl );

  _report  = 'The remote host supports the Home Network Administration Protocol (HNAP) / DHMAPI.\n\n';
  _report += 'Discovery-URL: ' + conclUrl;
  if( strlen( report ) > 0 )
    _report += '\n\nExtracted Device information:\n' + report;

  log_message( data:_report, port:port );
}

exit( 0 );
