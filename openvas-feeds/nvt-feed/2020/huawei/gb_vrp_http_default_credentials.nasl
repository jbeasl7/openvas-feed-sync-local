# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108746");
  script_version("2025-05-28T05:40:15+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-05-28 05:40:15 +0000 (Wed, 28 May 2025)");
  script_tag(name:"creation_date", value:"2020-04-15 08:04:09 +0000 (Wed, 15 Apr 2020)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Default Accounts");
  script_name("Huawei VRP Default Credentials (HTTP)");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("huawei/vrp/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1000178166/1257fc63/what-is-the-default-login-password");
  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1000060368/25506195/understanding-the-list-of-default-user-names-and-passwords");
  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1000079719/1b8f7bdb/logging-in-to-an-ar-router-through-a-web-system");

  script_tag(name:"summary", value:"The remote Huawei Versatile Routing Platform (VRP) device is
  using known default credentials for the HTTP login.");

  script_tag(name:"vuldetect", value:"Tries to login via HTTP using known default credentials.");

  script_tag(name:"insight", value:"The remote Huawei Versatile Routing Platform (VRP) device is
  lacking a proper password configuration, which makes critical information and actions accessible
  for people with knowledge of the default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the default password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

# nb: Tested against:
# S5735-S24T4X with firmware V200R019C00SPC500
# AirEngine 5760-10 with firmware V200R019C00SPC300
# AR 6120 with firmware V300R019C00SPC300

CPE_PREFIX = "cpe:/o:huawei:";

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
CPE = infos["cpe"];

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

# nb: All three tested devices responded with a 301 and one of the following URLs:
# /simple/view/login.html (S5735-S24T4X)
# /view/loginPro.html (AR 6120)
# /view/login.html (AirEngine 5760-10)
# This will be used later to choose the correct Cookie / URL and post data
res = http_get_cache( port:port, item:"/" );
if( ! res || res !~ "^HTTP/1\.[01] 301" )
  exit( 0 );

if( "/simple/view/login.html" >< res )
  type = 0;
else if( "/view/loginPro.html" >< res )
  type = 1;
else if( "/view/login.html" >< res )
  type = 2;
else
  type = 3; # unknown, various requests below will be used.

creds = make_list(
  "admin:admin@huawei.com",
  "admin:admin",
  "admin:Admin@huawei",
  "admin:Admin@123",
  "root:admin",
  "super:sp-admin"
);

url = "/login.cgi";
headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );

foreach cred( creds ) {

  split = split( cred, sep:":", keep:FALSE );
  if( max_index( split ) != 2 )
    continue;

  username = split[0];
  password = split[1];
  valid_login = FALSE;

  # nb: Used post data depends on the type of the Web-GUI implementation on specific devices (see comment above)
  if( type == 0 )
    post_data_list = make_list( "UserName=" + username + "&Password=" + password + "&Edition=0" );
  else if( type == 1 || type == 2 )
    post_data_list = make_list( "UserName=" + username + "&Password=" + password + "&LanguageType=0" );
  else
    post_data_list = make_list( "UserName=" + username + "&Password=" + password + "&LanguageType=0",
                                "UserName=" + username + "&Password=" + password + "&Edition=0" );

  foreach post_data( post_data_list ) {

    req = http_post_put_req( port:port, url:url, data:post_data, add_headers:headers );
    res = http_keepalive_send_recv( port:port, data:req );
    if( ! res )
      continue;

    # nb: When doing the request on 80/tcp (which is redirecting to 443/tcp) then we're
    # getting a HTTP/1.1 403 Forbidden back so we're exiting directly so that we're not
    # unnecessarily checking the other credentials.
    if( res =~ "^HTTP/1\.[01] 403" )
      exit( 0 );

    # For a failed login the ErrorMsg=1008 is thrown but still we're getting a 200 back
    # so we need to check both.
    # nb: If the post data doesn't match the Web-GUI implementation of a specific device
    # we're getting a 400 status code back with a single "Bad Request" string in the body.
    if( res !~ "^HTTP/1\.[01] 200" || "ErrorMsg=1008" >< res )
      continue;

    # nb: All tested devices are providing / returning such a SessionID
    sessionid = http_get_cookie_from_header( buf:res, pattern:"(SessionID=[^;]+;)" );
    if( ! sessionid )
      continue;

    body = http_extract_body_from_response( data:res );
    if( ! body )
      continue;

    # If the "type" is "3" and we're getting the correct response we don't want to continue
    # with a possible second request.
    valid_login = TRUE;
    break;
  }

  # nb: No need to continue if the requests above are not valid (e.g. wrong credentials).
  if( ! valid_login )
    continue;

  # The response should look like e.g. for a valid account on "type == 0" :
  # NoChangeFlag=0&Location=/simple/view/main/main.html&Token=Pjx6Bpwd0tO6i3ky0OPnDMNIhAlgYKdn
  # and the following if a change of a password was requested (two different possibilities):
  # ChangeFlag=2&Token=iJYPmuHUKwqu0Dj5KiMd3zAZileTD4Bz&AAAMsg=
  # ChangeFlag=1&Token=iJYPmuHUKwqu0Dj5KiMd3zAZileTD4Bz&AAAMsg=
  #
  # for the AirEngine 5760-10 and AR 6120 we're just getting a 0 back in the body and without
  # the Token extracted later for the other device.
  location = eregmatch( string:body, pattern:"Location=([^&]+)", icase:FALSE );
  if( ! location[1] && ( "ChangeFlag=2" >< body || "ChangeFlag=1" >< body ) ) {
    if( type == 0 )
      urls = make_list( "/simple/view/main/modifyPwd.html" );
    else if( type == 1 )
      urls = make_list( "/professional/view/main/modifyPwd.html" );
    else if( type == 2 )
      urls = make_list( "/view/main/modifyPwd.html" );
    else
      urls = make_list( "/simple/view/main/modifyPwd.html", "/professional/view/main/modifyPwd.html", "/view/main/modifyPwd.html" );
  } else if( ! location[1] ) {
    if( type == 0 )
      urls = make_list( "/simple/view/main/main.html" );
    else if( type == 1 )
      urls = make_list( "/professional/view/main/default.html" );
    else if( type == 2 )
      urls = make_list( "/view/main/default.html" );
    else
      urls = make_list( "/simple/view/main/main.html", "/professional/view/main/default.html", "/view/main/default.html" ); # Fallback
  } else {
    urls = make_list( location[1] );
  }

  # nb: This is optional and depends on the Web-GUI implementation (the token is sometimes embedded directly into the html code as a "tTag" variable).
  token = eregmatch( string:body, pattern:"Token=([^&]+)", icase:FALSE );

  # Cookie should look like e.g.:
  # Cookie: LSWlanguage=lsw_lang_en.js; icbs_language=en; UserName=username; loginFlag=true; SessionID=CLkd5brguZa1xcvRMMxnrvqOijjGaGRl; Token=Pjx6Bpwd0tO6i3ky0OPnDMNIhAlgYKdn
  # OR this (depending on the Web-GUI implementation):
  # Cookie: loginUrl=loginPro; FactoryName=Huawei%20Technologies%20Co.; FactoryLogoUrl=../../images/; Package=NO; SessionID=pVjCDX4LjfayMN2lHCWOsRMus9SKFImN; ResetFlag=0; loginFlag=true; ARlanguage=property-en_CN.js
  # OR even this:
  # Cookie: resetFlag=6; language=property-en_CN.js; SessionID=l0Q8NcxZo6aCaFhQM7XU2zPubSwgv0Wg; userName=username

  if( type == 0 ) {
    cookie = "LSWlanguage=lsw_lang_en.js; icbs_language=en; UserName=" + username + "; loginFlag=true; " + sessionid;
    if( token[1] )
      cookie += " Token=" + token[1];
    cookies = make_list( cookie );
  }
  else if( type == 1 )
    cookies = make_list( "loginUrl=loginPro; FactoryName=Huawei%20Technologies%20Co.; FactoryLogoUrl=../../images/; Package=NO; " + sessionid + " ResetFlag=0; loginFlag=true; ARlanguage=property-en_CN.js" );
  else if( type == 2 )
    cookies = make_list( "resetFlag=0; language=property-en_CN.js; " + sessionid + " userName=" + username );
  else
    cookies = make_list( "LSWlanguage=lsw_lang_en.js; icbs_language=en; UserName=" + username + "; loginFlag=true; " + sessionid + " " + token[1],
                         "loginUrl=loginPro; FactoryName=Huawei%20Technologies%20Co.; FactoryLogoUrl=../../images/; Package=NO; " + sessionid + " ResetFlag=0; loginFlag=true; ARlanguage=property-en_CN.js",
                         "resetFlag=0; language=property-en_CN.js; " + sessionid + " userName=" + username );

  foreach cookie( cookies ) {

    headers = make_array( "Cookie" , cookie );
    valid_creds = FALSE;

    foreach url( urls ) {
      url = url + "?language=en";
      if( type == 2 )
        url += "&pageid=" + rand_str( length:5, charset:"0123456789" );

      req = http_get_req( port:port, url:url, add_headers:headers );
      res = http_keepalive_send_recv( port:port, data:req );
      if( ! res || res !~ "^HTTP/1\.[01] 200" )
        continue;

      if( 'icbs_lang="LG.publicModule.equ_board"' >< res || 'icbs_lang="LG.tree.common_maintenance"' >< res || "Current User: " + username >< res ||
          '<span id="current_login_userName"' >< res || 'onclick="confirmLogout' >< res || "icbs_lang=LG.publicModule.languageBtn" >< res) {
        VULN = TRUE;
        valid_creds = TRUE;
        report += '\nUsername: "' + username + '", Password: "' + password + '", URL: "' + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '"';
        break;
      } else if( "'loginCaption' id='oldPasswordCaption'" >< res || "'loginCaption' id='newPasswordCaption'" >< res ) {
        VULN = TRUE;
        valid_creds = TRUE;
        report += '\nUsername: "' + username + '", Password: "' + password + '" (The system is enforcing a change of the current password), URL: "' + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '"';
        break;
      }
    }

    if( valid_creds ) {
      # nb: Some devices are only able to handle a few logins so we're logging the user out to avoid blocking situations.
      # messageID is generated like e.g. messageId=Math.round(randomFun(1)*1000); with an internal randomFun function but it seems every random number is good.
      # htmlID is saved in the HTML source code and incremented on each page request. For type == 0 this doesn't exist, for the other types see below.
      if( type == 0 ) {
        # nb: Cookie doesn't include the loginFlag and the Token, the Token is a separate Header field.
        headers = make_array( "Referer", http_report_vuln_url( port:port, url:url, url_only:TRUE ), "Content-Type", "application/x-www-form-urlencoded; text/xml; charset=UTF-8", "Token", token[1], "Cookie", "LSWlanguage=lsw_lang_en.js; icbs_language=en; UserName=" + username + "; " + sessionid );
        message_id = rand_str( length:3, charset:"0123456789" );
        post_data = 'MessageID=' + message_id + '&<rpc message-id="' + message_id + '" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">\n<close-session/></rpc>]]>]]>';
        req = http_post_put_req( port:port, url:"/config.cgi", data:post_data, add_headers:headers );
        http_keepalive_send_recv( port:port, data:req );
      } else if( type == 1 ) {
        # nb: In this case the Cookie includes the loginFlag for some reason
        # We also need to extract the "Token" from a second page first
        # Cookie: loginUrl=loginPro; FactoryName=Huawei%20Technologies%20Co.; FactoryLogoUrl=../../images/; Package=NO; ResetFlag=0; loginFlag=true; ARlanguage=property-en_CN.js; SessionID=iWhQ4ihI0na7supa6EfMr9P9B1ZWDPZl
        req = http_get_req( port:port, url:"/professional/view/deviceSummary/equSummary.html", add_headers:headers );
        res = http_keepalive_send_recv( port:port, data:req );
        # tTag = "EL2Ycp6PH2al4LPS0GuSpYrilHZ9DTMD";
        token = eregmatch( string:res, pattern:'tTag = "([^"]+)";', icase:FALSE );
        headers = make_array( "Referer", http_report_vuln_url( port:port, url:url, url_only:TRUE ), "Content-Type", "application/x-www-form-urlencoded; text/xml; charset=UTF-8", "Token", token[1], "Cookie", cookie );
        message_id = rand_str( length:3, charset:"0123456789" );
        # See comment about htmlID above. We have two .html requests done so far so htmlID is 1001.
        post_data = 'htmlID=1001&MessageID=' + message_id + '&<rpc message-id="' + message_id + '" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">\n<close-session/></rpc>]]>]]>';
        req = http_post_put_req( port:port, url:"/professional/view/main/config.cgi", data:post_data, add_headers:headers );
        http_keepalive_send_recv( port:port, data:req );
      } else if( type == 2 ) {
        token = eregmatch( string:res, pattern:'tTag = "([^"]+)";', icase:FALSE );
        headers = make_array( "Referer", http_report_vuln_url( port:port, url:url, url_only:TRUE ), "Content-Type", "application/x-www-form-urlencoded; text/xml; charset=UTF-8", "Token", token[1], "Cookie", cookie );
        message_id = rand_str( length:3, charset:"0123456789" );
        # See comment about htmlID above. We have one .html request done so far so htmlID is 1000.
        post_data = 'htmlID=1000&MessageID=' + message_id + '&<rpc message-id="' + message_id + '" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">\n<close-session/></rpc>]]>]]>';
        req = http_post_put_req( port:port, url:"/config.cgi", data:post_data, add_headers:headers );
        http_keepalive_send_recv( port:port, data:req );
      }

      break;
    }
  }
}

if( VULN ) {
  report = 'It was possible to login with the following default credentials:\n' + report;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
