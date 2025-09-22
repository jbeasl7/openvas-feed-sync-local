# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:igniterealtime:openfire";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112307");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-06-15 10:04:21 +0200 (Fri, 15 Jun 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-20 00:15:00 +0000 (Thu, 20 Jun 2019)");

  script_cve_id("CVE-2018-11688");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Openfire < 3.9.2 Reflected XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openfire_http_detect.nasl");
  script_mandatory_keys("openfire/http/detected");
  script_require_ports("Services/www", 9090);

  script_tag(name:"summary", value:"Openfire is prone to a reflected cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Openfire is vulnerable to cross-site scripting caused by
  improper validation of user-supplied input.");

  script_tag(name:"impact", value:"A  remote attacker could exploit this vulnerability via a
  crafted URL to execute script in a victim's Web browser within the security context of the
  hosting web site, once the URL is clicked. An attacker could use this vulnerability to steal the
  victim's cookie-based authentication credentials.");

  script_tag(name:"affected", value:"Openfire prior to version 3.9.2.");

  script_tag(name:"solution", value:"Update to version 3.9.2 or later.");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2018/Jun/13");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2018/Jun/24");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

vtstrings = get_vt_strings();
data = vtstrings["lowercase"] + "_" + unixtime();
urls = make_list( 'login.jsp?url=a%22onclick=%22alert(' + data + ')', 'login.jsp?url=a"onclick="alert(' + data + ')' );

foreach url ( urls ) {
  req = http_get_req( port: port, url: dir + url );
  res = http_keepalive_send_recv( port: port, data: req );

  if( '<input type="hidden" name="url" value="a"onclick="alert(' + data + ')' >< res ) {
    report = http_report_vuln_url(  port: port, url: url );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
