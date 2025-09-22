# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100201");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-14 20:19:12 +0200 (Thu, 14 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("FormMail Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.scriptarchive.com/formmail.html");

  script_tag(name:"summary", value:"The FormMail Script was found at this port. FormMail is a generic HTML form to
e-mail gateway that parses the results of any form and sends them to the specified users.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

files = make_list( "formmail.pl", "formmail.pl.cgi", "FormMail.cgi", "FormMail.pl" );

foreach dir( make_list_unique( "/formmail", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" ) dir = "";

  foreach file( files ) {
    url = dir + "/" + file;
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
    if( isnull( buf ) ) continue;

    if( egrep( pattern:'FormMail', string:buf, icase:TRUE ) &&
        ( egrep( pattern:'A Free Product of', string:buf, icase:TRUE ) ||
          egrep( pattern:'Bad Referrer', string:buf, icase:TRUE ) ) ) {

      vers = "unknown";

      version = eregmatch( string:buf, pattern:'FormMail.*v([0-9.]+)', icase:TRUE );

      if (!isnull(version[1])) {
        vers = version[1];
        concUrl = url;
      }

      set_kb_item( name:"www/" + port + "/FormMail/file", value:file );
      set_kb_item( name:"FormMail/installed", value:TRUE );

      cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:matt_wright:formmail:" );
      if (!cpe )
        cpe = "cpe:/a:matt_wright:formmail";

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message(data: build_detection_report(app: "FormMail", version: vers, install: install, cpe: cpe,
                                               concluded: version[0], concludedUrl: concUrl),
                  port: port);
      exit( 0 );
    }
  }
}

exit( 0 );
