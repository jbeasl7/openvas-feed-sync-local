# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

#  Ref: Stefan Esser

CPE = "cpe:/a:s9y:serendipity";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15914");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2004-2525");
  script_xref(name:"OSVDB", value:"12177");
  script_name("Serendipity XSS Flaw");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("serendipity_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Serendipity/installed");
  script_tag(name:"solution", value:"Upgrade to Serendipity 0.7.1 or newer.");
  script_tag(name:"summary", value:"The remote version of Serendipity is vulnerable to cross-site scripting
attacks due to a lack of sanity checks on the 'searchTerm' parameter in
the 'compat.php' script.  With a specially crafted URL, an attacker can
cause arbitrary code execution in a user's browser resulting in a loss
of integrity.");
  script_xref(name:"URL", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=1076762&group_id=75065&atid=542822");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11790");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

if(!loc = get_app_location(cpe:CPE, port:port))exit(0);

req = http_get(item:string(loc, "/index.php?serendipity%5Baction%5D=search&serendipity%5BsearchTerm%5D=%3Cscript%3Efoo%3C%2Fscript%3E"), port:port);
r = http_keepalive_send_recv(port:port, data:req);
if( isnull( r ) ) exit( 0 );
if (r =~ "^HTTP/1\.[01] 200" && egrep(pattern:"<script>foo</script>", string:r))
{
  security_message(port);
}

