# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114987");
  script_cve_id("CVE-2004-1791");
  script_version("2025-03-26T05:38:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-26 05:38:58 +0000 (Wed, 26 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-24 13:43:00 +0000 (Mon, 24 Mar 2025)");
  script_name("Edimax Router Devices Default Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  # nb: No more specific detection attached / included here as there might be a wide range of
  # affected devices.
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Basic_realm/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210120100703/http://www.securityfocus.com/archive/1/349089");
  # nb: This one just shows the credentials as well:
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38056");

  script_tag(name:"summary", value:"The remote Edimax Router device is using known default
  credentials for the HTTP login.");

  script_tag(name:"vuldetect", value:"Checks if it is possible to login via HTTP with known
  default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"affected", value:"Edimax BR6228nS, BR6228nC, BR6428n, BR6258n, BR-6574N and
  AR-6004 devices are known to be affected. Other devices or vendors might be affected as well.");

  script_tag(name:"solution", value:"Login to the device and change the password of the affected
  account.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );
if( ! banner || banner !~ "WWW-Authenticate\s*:\s*Basic realm=" )
  exit( 0 );

url = "/";
# nb: No http_cache() as we want to grab a "fresh" response
req = http_get( item:url, port:port );
res1 = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

# WWW-Authenticate: Basic realm="Default: admin/1234"
if( ! res1 || res1 !~ "^HTTP/1\.[01] 401" || res1 !~ "Default: admin/1234" )
  exit( 0 );

# nb: No need for an array of credentials or similar here as this should only check for these
# specific credentials. Others will be tested in / via default_http_auth_credentials.nasl.
username = "admin";
password = "1234";

auth_header = make_array( "Authorization", "Basic " + base64( str:username + ":" + password ) );
req = http_get_req( port:port, url:url, add_headers:auth_header );
res2 = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

# nb:
# - Just a generic 200/302 status code as the previous pattern are already quite strict and we can't
#   check for some additional pattern of all affected model ranges / vendors.
# - At least BR6428n and BR6258n devices seems to have redirected to /index.asp after the login
# - An unknown "Broadband Router" device with a firmware date of "2008/11/03 08:33:04" had used the
#   200 status code
if( ! res2 || res2 !~ "^HTTP/1\.[01] (200|30.)" )
  exit( 0 );

report = "It was possible to login using the username '" + username + "' and the password '" + password + "'.";
report += '\n\nResponse without passing credentials:\n\n' + chomp( res1 );
report += '\n\nResponse after passing credentials (truncated):\n\n' + substr( chomp( res2 ), 0, 1500 );
security_message( port:port, data:report );
exit( 0 );
