# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114541");
  script_version("2024-05-03T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-05-03 05:05:25 +0000 (Fri, 03 May 2024)");
  script_tag(name:"creation_date", value:"2024-04-30 13:29:46 +0000 (Tue, 30 Apr 2024)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Express Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  # nb: No "expressjs/banner" script_mandatory_keys as the detection will happen on each subdir
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 3000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://expressjs.com");
  script_xref(name:"URL", value:"https://github.com/expressjs/express");
  script_xref(name:"URL", value:"https://nodejs.org");

  script_tag(name:"summary", value:"HTTP based detection of the Express Node.js web application
  framework and Node.js itself (based on the Express detection).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:3000 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";
  buf = http_get_cache( item:url, port:port );
  if( ! buf || buf !~ "^HTTP/1\.[01] " )
    continue;

  found = 0;

  # nb:
  # - Currently only rudimentary support based on the banner or the default page but we might want
  #   to check if we can detect this via other means as well. E.g. some systems had the following
  #   title: "<title>Express Status</title>"
  # - It seems that it is also possible to "hide" the banner via some config / code
  # - We exit on the first found URL / install path

  # Just the following for the banner:
  #
  # X-Powered-By: Express
  # x-powered-by: Express
  #
  if( concl = egrep( string:buf, pattern:"^[Xx]-[Pp]owered-[Bb]y\s*:\s*Express", icase:FALSE ) ) {
    # nb: Banner directly counts as two
    concluded = "  " + chomp( concl );
    found = 2;
  }

  # e.g. (in one single line):
  #
  # <!DOCTYPE html><html><head><title>Express on AWS</title><link rel="stylesheet" href="/stylesheets/style.css"></head><body><h1>Express on AWS</h1><p>Welcome to Express on AWS</p></body></html>
  #
  # or:
  #
  # <!DOCTYPE html><html><head><title>Express</title><link rel="stylesheet" href="/stylesheets/style.css"></head><body><h1>Express</h1><p>Welcome to Express</p></body></html>
  #
  if( concl = eregmatch( string:buf, pattern:"<(title|h1)>Express[^<]*</(title|h1)>", icase:FALSE ) ) {
    if( concluded )
      concluded += '\n';
    concluded += "  " + concl[0];
    found++;
  }

  if( concl = eregmatch( string:buf, pattern:"<p>Welcome to Express[^<]*</p>", icase:FALSE ) ) {
    if( concluded )
      concluded += '\n';
    concluded += "  " + concl[0];
    found++;
  }

  # nb: See note above
  if( found > 1 ) {
    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    break;
  }
}

# nb: Another try based on the standard 404 error page
if( found <= 1 ) {

  foreach file( make_list( "/", "/vt-test-non-existent.html", "/vt-test/vt-test-non-existent.html" ) ) {

    buf = http_get_cache( item:file, port:port, fetch404:TRUE );
    if( ! buf || buf !~ "^HTTP/1\.[01] 404" )
      continue;

    # e.g.:
    #
    # <body>
    # <pre>NotFoundError: Not Found<br> &nbsp; &nbsp;at <redacted>/dist/app.js:46:36<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (<redacted>/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at trim_prefix (<redacted>/node_modules/express/lib/router/index.js:317:13)<br> &nbsp; &nbsp;at <redacted>/node_modules/express/lib/router/index.js:284:7<br> &nbsp; &nbsp;at Function.process_params (<redacted>/node_modules/express/lib/router/index.js:335:12)<br> &nbsp; &nbsp;at next (<redacted>/node_modules/express/lib/router/index.js:275:10)<br> &nbsp; &nbsp;at SendStream.error (<redacted>/node_modules/serve-static/index.js:121:7)<br> &nbsp; &nbsp;at SendStream.emit (node:events:518:28)<br> &nbsp; &nbsp;at SendStream.emit (node:domain:488:12)<br> &nbsp; &nbsp;at SendStream.error (<redacted>/node_modules/send/index.js:270:17)</pre>
    # </body>
    # </html>
    #
    # or:
    #
    # <!DOCTYPE html><html><head><title></title><link rel="stylesheet" href="/stylesheets/style.css"></head><body><h1>Not Found</h1><h2>404</h2><pre>NotFoundError: Not Found
    #    at /<redacted>/app.js:27:8
    #    at Layer.handle [as handle_request] (/<redacted>/node_modules/express/lib/router/layer.js:95:5)
    #    at trim_prefix (/<redacted>/node_modules/express/lib/router/index.js:317:13)
    #    at /<redacted>/node_modules/express/lib/router/index.js:284:7
    #    at Function.process_params (/<redacted>/node_modules/express/lib/router/index.js:335:12)
    #    at next (/<redacted>/node_modules/express/lib/router/index.js:275:10)
    #    at /<redacted>/node_modules/express/lib/router/index.js:635:15
    #    at next (/<redacted>/node_modules/express/lib/router/index.js:260:14)
    #    at Function.handle (/<redacted>/node_modules/express/lib/router/index.js:174:3)
    #    at router (/<redacted>/node_modules/express/lib/router/index.js:47:12)</pre></body></html>
    #
    if( concl = eregmatch( string:buf, pattern:"<pre>NotFoundError\s*:\s*Not Found", icase:FALSE ) ) {
      if( concluded )
        concluded += '\n';
      concluded += "  " + concl[0];
      found++;
    }

    if( concl = eregmatch( string:buf, pattern:'at [^\r\n]*/node_modules/express/[^\r\n]+\\.js', icase:FALSE ) ) {
      if( concluded )
        concluded += '\n';
      concluded += "  " + concl[0];
      found++;
    }

    # nb: See note above
    if( found > 1 ) {
      if( conclUrl )
        conclUrl += '\n';
      conclUrl += "  " + http_report_vuln_url( port:port, url:file, url_only:TRUE );
      break;
    }
  }
}

if( found > 1 ) {

  version = "unknown";

  set_kb_item( name:"expressjs/detected", value:TRUE );
  set_kb_item( name:"expressjs/http/detected", value:TRUE );
  set_kb_item( name:"nodejs/detected", value:TRUE );
  set_kb_item( name:"nodejs/http/detected", value:TRUE );

  # nb:
  # - Cross-check this CPE once CVE-2024-29041 got a CPE assigned
  # - For now the CPE has been created based on the vendor URL and Github project name
  express_cpe = "cpe:/a:expressjs:express";

  # nb: If Express is found we can also register and report Node.js itself
  node_cpe = "cpe:/a:nodejs:node.js";

  register_product( cpe:express_cpe, location:install, port:port, service:"www" );
  register_product( cpe:node_cpe, location:install, port:port, service:"www" );

  report = build_detection_report( app:"Express", version:version,
                                   install:install, cpe:express_cpe );
  report += '\n\n';
  report += build_detection_report( app:"Node.js", version:version,
                                    install:install, cpe:node_cpe );
  report += '\n\n';
  report += 'Concluded from version/product identification result:\n' + concluded + '\n\n';
  report += 'Concluded from version/product identification location:\n' + conclUrl;

  log_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
