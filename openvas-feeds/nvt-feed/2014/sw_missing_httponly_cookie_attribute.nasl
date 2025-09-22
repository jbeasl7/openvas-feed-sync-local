# SPDX-FileCopyrightText: 2014 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105925");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2014-09-01 16:00:00 +0100 (Mon, 01 Sep 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Missing 'HttpOnly' Cookie Attribute (HTTP)");
  script_copyright("Copyright (C) 2014 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.rfc-editor.org/rfc/rfc6265#section-5.2.6");
  script_xref(name:"URL", value:"https://owasp.org/www-community/HttpOnly");
  script_xref(name:"URL", value:"https://wiki.owasp.org/index.php/Testing_for_cookies_attributes_(OTG-SESS-002)");

  script_tag(name:"summary", value:"The remote HTTP web server / application is missing to set the
  'HttpOnly' cookie attribute for one or more sent HTTP cookie.");

  script_tag(name:"vuldetect", value:"Checks all cookies sent by the remote HTTP web server /
  application for a missing 'HttpOnly' cookie attribute.");

  script_tag(name:"insight", value:"The flaw exists if a session cookie is not using the 'HttpOnly'
  cookie attribute.

  This allows a cookie to be accessed by JavaScript which could lead to session hijacking
  attacks.");

  script_tag(name:"affected", value:"Any web application with session handling in cookies.");

  script_tag(name:"solution", value:"- Set the 'HttpOnly' cookie attribute for any session cookie

  - Evaluate / do an own assessment of the security impact on the web server / application and create
  an override for this result if there is none (this can't be checked automatically by this VT)");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

res = http_get_cache( item:"/", port:port );

if( res && res =~ "Set-Cookie\s*:.+" ) {

  cookies = egrep( string:res, pattern:"^Set-Cookie\s*:.+", icase:TRUE );

  if( cookies ) {

    cookiesList = split( cookies, sep:'\n', keep:FALSE );
    vuln = FALSE;

    foreach cookie( cookiesList ) {

      if( cookie !~ ";[ ]?[H|h]ttp[O|o]nly?[^a-zA-Z0-9_-]?" ) {
        # Clean-up cookies from dynamic data so we don't report differences on the delta report
        pattern = "([Ss]et-[Cc]ookie\s*:.*=)([a-zA-Z0-9]+)(;.*)";
        if( eregmatch( pattern:pattern, string:cookie ) ) {
          cookie = ereg_replace( string:cookie, pattern:pattern, replace:"\1***replaced***\3" );
        }
        vuln = TRUE;
        vulnCookies += cookie + '\n';
      }
    }

    if( vuln ) {
      report = 'The cookie(s):\n\n' + vulnCookies + '\nis/are missing the "HttpOnly" cookie attribute.';
      security_message( port:port, data:chomp( report ) );
      exit( 0 );
    }
  }
}

exit( 99 );
