# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101000");
  script_version("2024-04-17T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-04-17 05:05:27 +0000 (Wed, 17 Apr 2024)");
  script_tag(name:"creation_date", value:"2009-03-08 14:50:37 +0100 (Sun, 08 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2000-0746", "CVE-2000-1104");
  script_name("Microsoft IIS XSS Vulnerability (MS00-060) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-060");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1594");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1595");

  script_tag(name:"summary", value:"Microsoft IIS do not properly protect against cross-site
  scripting (XSS) attacks.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"They allow a malicious web site operator to embed scripts in a
  link to a trusted site, which are returned without quoting in an error message back to the client.
  The client then executes those scripts in the same context as the trusted site.");

  script_tag(name:"affected", value:"Microsoft IIS 4.0 and 5.0 is known to be affected.");

  script_tag(name:"solution", value:"Microsoft has released a patch to correct these issues. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  # nb: Response check doesn't look that reliable these days...
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/_vti_bin/shtml.dll/<script>alert(1)</script>";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res ) {
  if( ( "Microsoft-IIS" >< res ) && ( egrep( pattern:"^HTTP/1\.[01] 200", string:res, icase:TRUE ) ) && ( "<script>(1)</script>" >< res ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
