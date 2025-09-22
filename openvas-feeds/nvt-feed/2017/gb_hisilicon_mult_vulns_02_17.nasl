# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140171");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2025-09-12T05:38:45+0000");

  script_name("HiSilicon ASIC Firmware Multiple Vulnerabilities (Feb 2017) - Active Check");

  script_xref(name:"URL", value:"https://ssd-disclosure.com/ssd-advisory-hisilicon-multiple-vulnerabilities/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44004");

  script_tag(name:"vuldetect", value:"Try to read /etc/passwd.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"HiSilicon ASIC firmware are prone to multiple vulnerabilities:

  1. Buffer overflow in built-in webserver

  2. Directory path traversal built-in webserver");

  script_tag(name:"affected", value:"Vendors using the HiSilicon application-specific integrated
  circuit (ASIC) chip set in their products.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-02-22 10:07:23 +0100 (Wed, 22 Feb 2017)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("uc_httpd/banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("traversal_func.inc");

port = http_get_port( default:80 );

files = traversal_files("linux");

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = "../../" + file;
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( string:buf, pattern:pattern, icase:TRUE ) ) {
    report = 'By requesting `' + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '` it was possible to read `/' + file + '`. Response:\n\n' + buf + '\n';
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
