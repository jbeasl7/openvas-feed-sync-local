# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103683");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-03-20 16:20:02 +0100 (Wed, 20 Mar 2013)");
  script_name("Aastra OpenCom Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Aastra OpenCom.

  The script sends a connection request to the server and attempts to
  determine the model from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

foreach url( make_list( "/", "/index.html", "/home.asp?state=0" ) ) {

 buf = http_get_cache( item:url, port:port );

 if("<title>opencom" >!< tolower(buf))continue;

 typ = eregmatch(pattern:"<TITLE>OpenCom ([^<]+)</TITLE>", string:buf, icase:TRUE);

 if(isnull(typ[1])) {
   model = "unknown";
   cpe = 'cpe:/h:aastra_telecom:opencom';
 } else {
   model = typ[1];
   cpe = 'cpe:/h:aastra_telecom:opencom_' + tolower(model);
 }

 register_product(cpe:cpe, location:url, port:port, service:"www");
 set_kb_item(name:"aastra_opencom/model", value: model);

 log_message(data: build_detection_report(app:"Detected Aastra OpenCom", version:model, install:url, cpe:cpe, concluded: typ[0]),
             port:port);
 exit(0);
}

exit(0);
