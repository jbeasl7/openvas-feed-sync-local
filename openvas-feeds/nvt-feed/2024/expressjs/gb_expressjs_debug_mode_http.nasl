# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:expressjs:express";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114542");
  script_version("2024-06-10T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-10 05:05:40 +0000 (Mon, 10 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-04-30 13:29:46 +0000 (Tue, 30 Apr 2024)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"cvss_base", value:"5.0");
  script_name("Express NODE_ENV 'development' Information Disclosure Vulnerability (HTTP) - Active Check");
  script_category(ACT_ATTACK); # nb: Might be already seen as an attack
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_dependencies("gb_expressjs_http_detect.nasl");
  script_require_ports("Services/www", 3000);
  script_mandatory_keys("expressjs/http/detected");

  script_xref(name:"URL", value:"https://expressjs.com/en/advanced/best-practice-performance.html#set-node_env-to-production");
  script_xref(name:"URL", value:"https://www.synopsys.com/blogs/software-security/nodejs-mean-stack-vulnerabilities.html");

  script_tag(name:"summary", value:"Express is prone to an information disclosure vulnerability if
  the NODE_ENV environment variable is set to 'development'.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"By default, Express applications run in development mode unless
  the NODE_ENV environmental variable is set to another value.");

  script_tag(name:"impact", value:"In development mode, Express returns more verbose errors which
  can result in information leakage.");

  script_tag(name:"affected", value:"Express applications having the NODE_ENV environment variable
  set to the 'development' default.");

  script_tag(name:"solution", value:"Set the NODE_ENV environment variable to 'production'. Please
  see the references for more information.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/";

host = http_host_name( port:port );
vt_strings = get_vt_strings();
body = vt_strings["lowercase_rand"];

# nb: Not using http_get* here as we only want this "pure" HTTP GET request
req  = "GET " + url + ' HTTP/1.1\r\n';
req += "Host: " + host + '\r\n';
req += 'Content-Type: application/json\r\n';
req += 'Connection: close\r\n';
req += "Content-Length: " + strlen( body ) + '\r\n\r\n';
req += body;

# nb: Don't use http_keepalive_send_recv() as we don't want to modify the HTTP GET request created
# previously (which would be done by that function).
res = http_send_recv( port:port, data:req, bodyonly:FALSE );

# nb: We should get a "400 Bad Request" here
if( ! res || res !~ "^HTTP/1\.[01] 400" )
  exit( 0 );

if( ! body = http_extract_body_from_response( data:res ) )
  exit( 0 );

# e.g.:
#
# <!DOCTYPE html><html><head><title></title><link rel="stylesheet" href="/stylesheets/style.css"></head><body><h1>Unexpected token 'g', &quot;#&quot; is not valid JSON</h1><h2>400</h2><pre>SyntaxError: Unexpected token 'g', &quot;#&quot; is not valid JSON
#    at JSON.parse (&lt;anonymous&gt;)
#    at createStrictSyntaxError (/<redacted>/node_modules/body-parser/lib/types/json.js:158:10)
# *snip*
#
# or:
#
# <title>Error</title>
# </head>
# <body>
# <pre>SyntaxError: Unexpected token g<br> &nbsp; &nbsp;at Object.parse (native)<br> &nbsp; &nbsp;at createStrictSyntaxError (/<redacted>/node_modules/body-parser/lib/types/json.js:158:10)<br> &nbsp; &nbsp;at parse (/<redacted>/node_modules/body-parser/lib/types/json.js:83:15)<br> &nbsp; &nbsp;at /<redacted>/node_modules/body-parser/lib/read.js:121:18<br> &nbsp; &nbsp;at invokeCallback (/<redacted>/node_modules/raw-body/index.js:224:16)<br> &nbsp; &nbsp;at done (/<redacted>/node_modules/raw-body/index.js:213:7)<br> &nbsp; &nbsp;at IncomingMessage.onEnd (/<redacted>/node_modules/raw-body/index.js:273:7)<br> &nbsp; &nbsp;at IncomingMessage.emit (events.js:92:17)<br> &nbsp; &nbsp;at _stream_readable.js:943:16<br> &nbsp; &nbsp;at process._tickCallback (node.js:419:13)</pre>
# </body>
#
# nb: The 'g' is the first letter from the string passed in the body of the HTTP GET request above.
#
if( egrep( string:res, pattern:"(>SyntaxError\s*:\s*Unexpected token .+|at .*/node_modules/.+\.js)", icase:FALSE ) ) {
  report  = 'By doing the following HTTP request:\n\n';
  report += req;
  report += '\n\nit was possible to trigger the following stacktrace / response including sensitive application information:\n';
  report += chomp( body );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
