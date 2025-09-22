# SPDX-FileCopyrightText: 2001 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10756");
  script_version("2023-08-01T13:29:10+0000");
  script_cve_id("CVE-2016-1776", "CVE-2018-6470");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-20 02:59:00 +0000 (Tue, 20 Dec 2016)");
  script_name("MacOS X Finder '.DS_Store' Information Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3316");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3324");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85054");
  script_xref(name:"URL", value:"https://helpx.adobe.com/dreamweaver/kb/remove-ds-store-files-mac.html");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT1629");

  script_tag(name:"solution", value:"Block access to hidden files (starting with a dot) within your webservers
  configuration");

  script_tag(name:"summary", value:"MacOS X creates a hidden file '.DS_Store', in each directory that has been viewed
  with the 'Finder'. This file contains a list of the contents of the directory, giving an attacker
  information on the structure and contents of your website.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

report = 'The following files were identified:\n';

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/.DS_Store";
  res = http_get_cache( port:port, item:url );
  if( res =~ "^HTTP/1\.[01] 200" && "Bud1" >< res ) {
    report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    found   = TRUE;
  }
}

if( found ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
