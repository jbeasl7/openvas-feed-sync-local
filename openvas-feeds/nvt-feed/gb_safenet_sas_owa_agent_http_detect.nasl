# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:outlook_web_app";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105151");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2014-12-22 14:36:28 +0100 (Mon, 22 Dec 2014)");
  script_name("SafeNet SAS OWA Agent Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_microsoft_exchange_outlook_web_app_http_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("microsoft/exchange_server/outlook_web_app/http/detected");

  script_tag(name:"summary", value:"HTTP based detection of the SafeNet Authentication Service (SAS)
  Outlook Web Access (OWA) Agent (formerly CRYPTOCard).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/owa/auth/logon.aspx?replaceCurrent=1&url=";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "title>CRYPTOCard Authentication Form - Outlook Web Access" >< buf && "CRYPTOCard Microsoft Exchange Plugin" >< buf ) {

  # nb: No need to register an OS (Windows) here because this is already done / handled by the
  # existing OWA detection.
  cpe = "cpe:/a:safenet-inc:safenet_authentication_service_outlook_web_access_agent";

  set_kb_item( name:"safenet/sas_owa_agent/detected", value:TRUE );
  set_kb_item( name:"safenet/sas_owa_agent/http/detected", value:TRUE );

  register_product( cpe:cpe, location:"/", port:port, service:"www" );

  log_message( data:'Detected SafeNet SAS OWA Agent\nCPE: ' + cpe + '\nLocation: ' + url, port:port );
  exit( 0 );
}

exit( 0 );
