# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nuuo:nuuo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105856");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2016-08-08 19:16:36 +0200 (Mon, 08 Aug 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:19:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2016-6553");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("NUUO Network Video Recorder Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_nuuo_devices_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nuuo/device/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote NUUO Network Video Recorder web interface is using
  known default credentials.");

  script_tag(name:"vuldetect", value:"Tries to login with default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93807");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

credentials = make_list( "admin:admin",
                         "localdisplay:111111" );

url = "/login.php";

foreach creds( credentials ) {
  creds = split( creds, sep:":", keep:FALSE );
  username = creds[0];
  password = creds[1];

  # nb: We need to get every time a new cookie to avoid false-positives
  req = http_get( port:port, item:"/" );
  res = http_keepalive_send_recv( port:port, data:req );

  cookie = http_get_cookie_from_header( buf:res, pattern: "(PHPSESSID=[^; ]+)");
  if( isnull( cookie ) )
    exit(0);

  headers = make_array( "Content-Type", "application/x-www-form-urlencoded",
                        "Cookie", cookie + "; loginName=" + username );

  data = "language=en&user=" + username + "&pass=" + password;

  req = http_post_put_req( port:port, url:url, data:data, add_headers:headers );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "cmd=loginfail" >< res )
    continue;

  url = "/setting.php";

  headers = make_array( "Cookie", cookie );

  req = http_get_req( port:port, url:url, add_headers:headers );
  res = http_keepalive_send_recv( port:port, data:req );

  if( '<span class="productName">' >< res || '<div id="official_fw_ver">' >< res ) {
    report += '\nUsername: "' + username + '", Password: "' + password + '"\n';

    product_match = eregmatch( pattern:'<span class="productName">([A-Z0-9-]+)</span>', string:res );
    if( ! isnull( product_match[1] ) )
      product = product_match[1];
  }
}

# nb: This is placed outside the loop to not be reported multiple times if multiple logins were possible.
if( product )
  report += '\nThe running device is a NUUO ' + product + '.';

if (report) {
  report = 'It was possible to login with the following credentials:\n' + chomp( report );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
