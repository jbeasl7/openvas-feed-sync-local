# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806035");
  script_version("2025-03-25T05:38:56+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-25 05:38:56 +0000 (Tue, 25 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-09-02 15:50:18 +0530 (Wed, 02 Sep 2015)");
  script_name("Edimax Products Multiple Vulnerabilities (Sep 2015) - Active Check");
  # nb: Only a standard GET request so no ACT_ATTACK
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  # nb: No more specific detection attached / included here as there might be a wide range of
  # affected devices.
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Basic_realm/banner");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38056");

  script_tag(name:"summary", value:"Edimax products are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.

  Note: This checks if `/FUNCTION_SCRIPT` is accessible without authentication which indicates that
  the system is affected by the other vulnerabilities as well.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A cross-site scripting (XSS) vulnerability

  - A HTTP response splitting vulnerability

  - A cross-site request forgery (CSRF) vulnerability

  - Unprotected files / files without authorisation");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary script code in a user's browser, bypass authentication and read arbitrary files to
  obtain detail information about products.");

  script_tag(name:"affected", value:"Edimax BR6228nS/BR6228nC devices with firmware version 1.22 are
  known to be affected. Other versions, models or vendors might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );
if( ! banner || banner !~ "WWW-Authenticate\s*:\s*Basic realm=" )
  exit( 0 );

url = "/";
# nb: No http_cache() as we want to grab a "fresh" response
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

# WWW-Authenticate: Basic realm="Default: admin/1234"
if( ! res || res !~ "^HTTP/1\.[01] 401" || res !~ "Default: admin/1234" )
  exit( 0 );

url = "/FUNCTION_SCRIPT";
# nb: For this one we can use http_get_cache()
res = http_get_cache( item:url, port:port );

# _MODE_="EdimaxOBM"
# _MODE_="EdimaxOBML"
# _MODE_="Edimax"
# _MODEL_="BR6228GNS"
# _PLATFORM_="RTL8196C_1200"
# _WIRELESS_DRIVER_VERSION_="20"
if( res =~ "^HTTP/1\.[01] 200" &&
    egrep( string:res, pattern:'MODE_="Edimax[^"]*"', icase:FALSE ) &&
    egrep( string:res, pattern:'(WIRELESS_DRIVER_VERSION_="[0-9]+"|_(MODEL|PLATFORM)_="[^"]+")', icase:FALSE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  report += '\n\nResponse:\n\n' + res;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
