# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# SPDX-FileCopyrightText: Improved code and additional detection routines since 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111074");
  script_version("2025-03-14T15:40:32+0000");
  # nb:
  # - CVE-2023-37599 has currently a CVSSv3 score of 7.5 but we're using a lower score below on
  #   purpose as this product is not necessarily running on the target
  # - CVE-1999-0569 also has a CVSSv2 score of 10.0 which is too high as well
  # - Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #   avoid too large diffs.
  script_cve_id("CVE-1999-0569",
                "CVE-2023-37599", # nb: See https://github.com/sahiloj/CVE-2023-37599
                "CVE-2024-1076" # nb: See https://wpscan.com/vulnerability/9c3e9c72-3d6c-4e2c-bb8a-f4efce1371d5/
               );
  script_tag(name:"last_modification", value:"2025-03-14 15:40:32 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-12-26 15:00:00 +0100 (Sat, 26 Dec 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Enabled Directory Listing/Indexing Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://wiki.owasp.org/index.php/OWASP_Periodic_Table_of_Vulnerabilities_-_Directory_Indexing");

  script_tag(name:"summary", value:"The script attempts to identify directories with an enabled
  directory listing/indexing on a remote web server.");

  script_tag(name:"vuldetect", value:"Checks previously detected directories on a remote web server
  if a directory listing/indexing is enabled.

  Note: This check has a low QoD (Quality of Detection) value as it is not possible to automatically
  determine if the directory listing/indexing has been enabled on purpose (which is also a valid use
  case for some software products).");

  script_tag(name:"impact", value:"Based on the information shown an attacker might be able to
  gather additional info about the structure of this application.");

  script_tag(name:"affected", value:"Web servers with an enabled directory listing/indexing.");

  script_tag(name:"solution", value:"If not needed disable the directory listing/indexing within the
  web servers config.");

  script_tag(name:"solution_type", value:"Mitigation");
  # nb: Might not contain sensitive data / was configured on purpose
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

found = FALSE;
foundList = make_list();

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  buf = http_get_cache( item:dir + "/", port:port );
  if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
    continue;

  # nb / important: Keep the matchers below in sync with the ones in webmirror.nasl

  # <title>Index for / - SabreDAV 1.8.12-stable</title>
  # <h1>Index for /</h1>
  # <TITLE>Directory listing of /</TITLE>
  # <H1>Directory listing for /</H1>
  # <title>Directory listing for /</title>
  # <h2>Directory listing for /</h2>
  # <title>Directory Listing For /</title>
  # <h1>Directory Listing For /</h1>
  # <title>Index of /</title>
  # <h1>Index of /</h1>
  if( egrep( string:buf, pattern:">(Directory listing|Index) (for|of) /[^<]*<", icase:TRUE ) ) {
    foundList = make_list( foundList, http_report_vuln_url( port:port, url:install, url_only:TRUE ) );
    found = TRUE;
    continue; # nb: No need to evaluate the next pattern if we already have a match...
  }

  # Jetty dir listing, e.g.:
  #
  # <title>Directory: /</title>
  # <h1 class="title">Directory: /</h1>
  # <TITLE>Directory: /</TITLE>
  # <H1>Directory: /</H1>
  #
  # nb: "=~" is case insensitive so no specific handling for the lower/uppercase seen above required
  if( buf =~ "<TITLE>Directory: /" && buf =~ "<H1[^>]*>Directory: /" ) {
    foundList = make_list( foundList, http_report_vuln_url( port:port, url:install, url_only:TRUE ) );
    found = TRUE;
    continue; # nb: No need to evaluate the next pattern if we already have a match...
  }

  # Probably Microsoft IIS, e.g.:
  #
  # <title>redactedip - /docs/</title></head><body><H1>redactedip - /docs/</H1>
  # <pre><A HREF="/">[To Parent Directory]</A><br><br>
  if( ">[To Parent Directory]<" >< buf ) {
    foundList = make_list( foundList, http_report_vuln_url( port:port, url:install, url_only:TRUE ) );
    found = TRUE;
    continue; # nb: No need to evaluate the next pattern if we already have a match...
  }

  # nb: Do avoid false positives for e.g. an empty "<title>" matcher
  if( dir && dir != "" ) {
    if( egrep( string:buf, pattern:"<title>" + dir, icase:TRUE ) ) {
      foundList = make_list( foundList, http_report_vuln_url( port:port, url:install, url_only:TRUE ) );
      found = TRUE;
    }
  }
}

if( found ) {

  report = 'The following directories with an enabled directory listing/indexing were identified:\n\n';

  # nb: Sort to not report changes on delta reports if just the order is different
  foundList = sort( foundList );

  foreach tmpFound( foundList )
    report += tmpFound + '\n';

  report += '\nPlease review the content manually.';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
