# SPDX-FileCopyrightText: 2005 SensePost
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18424");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2271");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11620");
  script_xref(name:"OSVDB", value:"11530");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MiniShare webserver buffer overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SensePost");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"MiniShare 1.4.1 and prior versions are affected by a buffer overflow flaw.");

  script_tag(name:"impact", value:"A remote attacker could execute arbitrary commands by sending a specially
  crafted file name in a the GET request.");

  script_tag(name:"affected", value:"Version 1.3.4 and below do not seem to be vulnerable.");

  script_tag(name:"solution", value:"Upgrade to MiniShare 1.4.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

res = http_get_cache( item:"/", port:port );
if(!res || "<title>MiniShare</title>" >!< res)
  exit( 0 );

if( egrep( string:res, pattern:'<p class="versioninfo"><a href="http://minishare\\.sourceforge\\.net/">MiniShare 1\\.(3\\.([4-9][^0-9]|[0-9][0-9])|4\\.[01][^0-9])' ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
