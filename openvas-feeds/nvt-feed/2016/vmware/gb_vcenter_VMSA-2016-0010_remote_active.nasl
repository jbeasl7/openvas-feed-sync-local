# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:vcenter_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105854");
  script_cve_id("CVE-2016-5331");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2026-04-28T06:28:06+0000");

  script_name("VMware Security Updates for vCenter Server (VMSA-2016-0010) - Active Check");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0010.html");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Update to version 6.0 U2 or later.");

  script_tag(name:"summary", value:"vCenter contain an HTTP header injection vulnerability due to
  lack of input validation.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to set arbitrary HTTP response
  headers and cookies, which may allow for cross-site scripting and malicious redirect attacks.");

  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 20:00:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-08-08 14:06:24 +0200 (Mon, 08 Aug 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_vmware_vcenter_server_consolidation.nasl");
  script_mandatory_keys("vmware/vcenter/server/http/detected");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( port:port, cpe:CPE, nofork:TRUE ) )
  exit( 0 );

vtstrings = get_vt_strings();
vtstring = vtstrings["default"];
vtstring_lo = vtstrings["lowercase"];

co = 'Set-Cookie:%20' + vtstring + '=' + rand();
co_s = str_replace( string:co, find:'%20', replace:' ');

h1 = vtstring_lo + ':%20' + rand();
h1_s = str_replace( string:h1, find:'%20', replace:' ');

url = '/?syss%0d%0a' + co + '%0d%0a' + h1;

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "^HTTP/1\.[01] 303" ) {
  if( egrep( pattern:'^' + co_s, string:buf ) && egrep( pattern:'^' + h1_s, string:buf ) ) {
    report = http_report_vuln_url( port:port, url:url );
    report += '\n\nResponse:\n\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );