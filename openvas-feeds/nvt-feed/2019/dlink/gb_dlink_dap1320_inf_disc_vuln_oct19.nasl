# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113546");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2019-10-23 11:41:42 +0200 (Wed, 23 Oct 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2019-17505");

  script_name("D-Link DAP-1320 A2-V1.21 Routers Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");

  # nb: Experiences in the past have shown that various different devices could be affected
  script_dependencies("gb_dlink_dsl_consolidation.nasl", "gb_dlink_dap_consolidation.nasl",
                      "gb_dlink_dir_consolidation.nasl", "gb_dlink_dwr_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("d-link/http/detected");

  script_tag(name:"summary", value:"D-Link DAP-1320 routers are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to acquire sensitive information.");

  script_tag(name:"insight", value:"The file uplink_info.xml doesn't require authorization and
  contains the SSID and PSK password.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain the Wi-Fi
  credentials.");

  script_tag(name:"affected", value:"D-Link DAP-1320 A2 routers through firmware version 1.21.
  Other devices might also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://github.com/dahua966/Routers-vuls/blob/master/DAP-1320/vuls_poc.md");

  exit(0);
}

CPE_PREFIX = "cpe:/o:dlink";

include( "host_details.inc" );
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

vuln_url = dir + "/uplink_info.xml";

buf = http_get_cache( port: port, item: vuln_url );

if( buf =~ "^HTTP/1\.[01] 200" ) {

  ssid = eregmatch( string: buf, pattern: '<wlan[0-9]?_ssid>([^<]+)</wlan[0-9]?_ssid>', icase: TRUE );
  psk = eregmatch( string: buf, pattern: '<wlan[0-9]?_psk_pass_phrase>([^<]+)</wlan[0-9]?_psk_pass_phrase>', icase: TRUE );

  if( ! isnull( ssid[1] ) && ! isnull( psk[1] ) ) {
    report = http_report_vuln_url( port: port, url: vuln_url );
    report += '\nIt was possible to acquire the following Wi-Fi credentials:\n';
    report += 'SSID: ' + ssid[1] + '\nPSK:  ' + psk[1];
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
