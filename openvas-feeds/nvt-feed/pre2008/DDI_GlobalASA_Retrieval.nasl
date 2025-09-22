# SPDX-FileCopyrightText: 2001 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10991");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("Microsoft Internet Information Services (IIS) Global.asa Retrieval");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Digital Defense Inc.");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_tag(name:"solution", value:"To restore the .asa map:

  Open Internet Services Manager. Right-click on the affected web server and choose Properties
  from the context menu. Select Master Properties, then Select WWW Service --> Edit --> Home
  Directory --> Configuration. Click the Add button, specify C:\winnt\system32\inetsrv\asp.dll
  as the executable (may be different depending on your installation), enter .asa as the extension,
  limit the verbs to GET, HEAD, POST, TRACE, ensure the Script Engine box is checked and click OK.");

  script_tag(name:"summary", value:"This host is running the Microsoft IIS web server. This web server contains
  a configuration flaw that allows the retrieval of the global.asa file.");

  script_tag(name:"impact", value:"This file may contain sensitive information such as database passwords,
  internal addresses, and web application configuration options.");

  script_tag(name:"insight", value:"This vulnerability may be caused by a missing ISAPI map of the .asa extension
  to asp.dll.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/global.asa";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( "RUNAT" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  set_kb_item( name:"iis/global.asa.download", value:TRUE );
  exit( 0 );
}

exit( 99 );
