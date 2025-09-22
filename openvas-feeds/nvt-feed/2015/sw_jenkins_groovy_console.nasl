# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111002");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-03-02 12:00:00 +0100 (Mon, 02 Mar 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Jenkins CI Groovy Console accessible");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("gb_jenkins_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("jenkins/detected");

  script_tag(name:"summary", value:"Checks if the Jenkins CI Groovy Console is unprotected.");

  script_tag(name:"impact", value:"The Groovy Console allows an attacker to execute
  operating system commands with the permissions of the user running the service.");

  script_tag(name:"vuldetect", value:"The script sends a HTTP request to the
  server and checks if the Groovy Console is unprotected.");

  script_tag(name:"solution", value:"Protect the access to the Groovy Console by
  configuring user accounts. Please see the reference for more information.");

  script_xref(name:"URL", value:"https://wiki.jenkins-ci.org/display/JENKINS/Securing+Jenkins");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/script";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Script Console" >< buf && "Groovy script" >< buf ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
