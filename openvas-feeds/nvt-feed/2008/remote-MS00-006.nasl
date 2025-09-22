# SPDX-FileCopyrightText: 2008 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80007");
  script_version("2024-04-17T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-04-17 05:05:27 +0000 (Wed, 17 Apr 2024)");
  script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0071", "CVE-2000-0097", "CVE-2000-0098", "CVE-2000-0302");
  script_name("Microsoft IIS WebHits ISAPI Filter Vulnerability (MS00-06) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2008 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-006.asp");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208184628/http://www.securityfocus.com/bid/1084/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208184628/http://www.securityfocus.com/bid/1065/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208184628/http://www.securityfocus.com/bid/950/");

  script_tag(name:"summary", value:"The WebHits ISAPI filter in Microsoft Index Server allows remote
  attackers to read arbitrary files, aka the 'Malformed Hit-Highlighting Argument' vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.

  Note: This VT checks for the existence of CVE-2000-0097.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  # nb: Response check doesn't look that reliable these days...
  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

foreach asp_file( make_list( "default.asp", "iisstart.asp", "localstart.asp", "index.asp" ) ) {

  url = string( "/null.htw?CiWebHitsFile=/" + asp_file + "%20&CiRestriction=none&CiHiliteType=Full" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res ) {
    r = tolower( res );
    if( "Microsoft-IIS" >< r && egrep( pattern:"^HTTP/1.[01] 200", string:r ) && "<html>" >< r ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
