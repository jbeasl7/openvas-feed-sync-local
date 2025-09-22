# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111097");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2015-2882");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Philips In.Sight Default Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-14 14:16:00 +0000 (Fri, 14 Apr 2017)");
  script_tag(name:"creation_date", value:"2016-04-24 12:00:00 +0200 (Sun, 24 Apr 2016)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "nmap_mac.nasl", "gb_default_credentials_options.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://www.ifc0nfig.com/a-close-look-at-the-philips-in-sight-ip-camera-range/");
  script_xref(name:"URL", value:"https://www.rapid7.com/docs/Hacking-IoT-A-Case-Study-on-Baby-Monitor-Exposures-and-Vulnerabilities.pdf");

  script_tag(name:"summary", value:"The remote Philips In.Sight Device has default credentials set.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials of admin:M100-4674448 or user:M100-4674448");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );

res = http_get_cache( item: "/", port:port );

if( "Philips InSight Wireless Home Monitor" >< res ) {

  # nb: MAC address set by nmap_mac.nasl
  mac = get_kb_item( "Host/mac_address" );

  if( mac ) {
    password = "i" + substr( hexstr( MD5( mac) ), 0, 9);
    creds = make_array( "admin", password,
                        "user", "M100-4674448" );
  } else {
    creds = make_array( "admin", "M100-4674448",
                        "user", "M100-4674448" );
  }

  urls = make_list( "/cgi-bin/v1/camera",
                    "/cgi-bin/v1/firmware/version",
                    "/cgi-bin/img-0.cgi",
                    "/cgi-bin/v1/stream0",
                    "/cgi-bin/v1/users/admin" );

  useragent = http_get_user_agent();
  host = http_host_name( port:port );

  foreach url( urls ) {

    foreach cred ( keys( creds ) ) {

      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req );

      if( "401 Unauthorized" >!< res || 'WWW-Authenticate: Digest realm="Authorization required"' >!< res || "nonce" >!< res ) continue;

      nonce = eregmatch( pattern:'nonce="([^"]+)', string:res );
      if( isnull( nonce[1] ) ) continue;

      nonce = nonce[1];
      cnonce = rand_str( charset:"abcdefghijklmnopqrstuvwxyz0123456789", length:16 );
      qop = "auth";
      nc = "00000001";

      ha1 = hexstr( MD5( string( cred,":Authorization required:",creds[cred] ) ) );
      ha2 = hexstr( MD5( string( "GET:",url ) ) );
      response = hexstr( MD5( string( ha1,":",nonce,":",nc,":",cnonce,":",qop,":",ha2 ) ) );

      req = 'GET ' + url + ' HTTP/1.1\r\n' +
            'Host: ' +  host + '\r\n' +
            'User-Agent: ' + useragent +'\r\n' +
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
            'Accept-Language: en-US,en;q=0.5\r\n' +
            'Content-Type: application/x-www-form-urlencoded\r\n' +
            'Authorization: Digest username="' + cred + '", realm="Authorization required", ' +
            'nonce="' + nonce + '", uri="' + url + '", ' +
            'response="' + response + '", qop=' + qop  + ', nc=' + nc  + ', ' +
            'cnonce="' + cnonce + '"\r\n' +
             '\r\n';
      res = http_keepalive_send_recv( port:port, data:req );

      if( res =~ "^HTTP/1\.[01] 200" ) {
        VULN = TRUE;
        report += http_report_vuln_url( url:url, port:port ) + ", Credentials: " + cred + ":" + creds[cred] + '\n';
      }
    }
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
