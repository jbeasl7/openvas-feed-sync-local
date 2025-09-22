# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801664");
  script_version("2023-08-15T05:05:29+0000");
  script_tag(name:"last_modification", value:"2023-08-15 05:05:29 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2010-12-21 15:42:46 +0100 (Tue, 21 Dec 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2010-1748");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS < 1.4.4 Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_cups_http_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("cups/http/detected");

  script_tag(name:"summary", value:"CUPS is prone to an information disclosure vulnerability.");

  script_tag(name:"insight", value:"This flaw is due to an error in 'cgi_initialize_string' function
  in 'cgi-bin/var.c' which mishandles input parameters containing the '%' character.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive
  information from cupsd process memory via a crafted request.");

  script_tag(name:"affected", value:"CUPS version 1.4.3 and prior.");

  script_tag(name:"solution", value:"Update to version 1.4.4 or later.");

  script_xref(name:"URL", value:"http://cups.org/str.php?L3577");
  script_xref(name:"URL", value:"http://cups.org/articles.php?L596");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40220");
  script_xref(name:"URL", value:"https://github.com/apple/cups/issues/3577");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( port:port, cpe:CPE, nofork:TRUE ) )
  exit( 0 );

url = "/admin?OP=redirect&URL=%";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( egrep( pattern:'^Location\\s*:.*%FF.*/cups/cgi-bin/admin\\.cgi', string:res ) ) {
  report = http_report_vuln_url( url:url, port:port );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
