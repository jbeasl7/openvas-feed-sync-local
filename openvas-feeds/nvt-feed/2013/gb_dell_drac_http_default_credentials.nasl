# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103681");
  script_version("2024-07-19T15:39:06+0000");
  script_tag(name:"last_modification", value:"2024-07-19 15:39:06 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-03-18 17:03:03 +0100 (Mon, 18 Mar 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Dell DRAC / iDRAC Default Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_dell_drac_idrac_consolidation.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("dell/idrac/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.dell.com/support/contents/en-us/videos/videoplayer/how-to-log-in-to-idrac9-with-the-default-password/6336297377112");
  script_xref(name:"URL", value:"https://www.dell.com/support/kbdoc/en-us/000177787/how-to-change-the-default-login-password-of-the-idrac-9");

  script_tag(name:"summary", value:"The remote Dell Remote Access Controller (DRAC) / Integrated
  Remote Access Controller (iDRAC) is using known default credentials for the HTTP login.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration without requiring authentication.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");

function check_iDRAC_default_login(cpe, port) {

  local_var cpe, port;
  local_var user, pass, urls, posts, login_success, login_fail;
  local_var url, post, buf, accept_header, headers, req, ls;

  user = "root";
  pass = "calvin";

  if(cpe =~ "^cpe:/a:dell:idrac4") {
    urls = make_list("/cgi/login");
    posts = make_list("user=" + user + "&hash=" + pass);
    login_success = make_list('top.location.replace("/cgi/main")');
  }

  else if(cpe =~ "^cpe:/a:dell:idrac5") {
    urls = make_list("/cgi-bin/webcgi/login");
    posts = make_list("user=" + user + "&password=" + pass);
    # - Successful login
    #   - HTTP/1.1 200 OK
    #   - <?xml version="1.0" encoding="UTF-8"?><?xml-stylesheet type="text/xsl" href="/cgi/locale/login_en.xsl" media="screen"?><drac>
    #     <privilege racPrivilege="0" login="0" cfg="0" cfguser="0" clearlog="0" servercontrol="0" console="0" vmedia="0" testalert="0" debug="0" />
    #     <CARD_IP>redacted</CARD_IP><OEM>0</OEM><MSG>0x0</MSG><LANG>en</LANG>
    #     <LOGIN><RESP><RC>0x3000</RC><SID>0</SID><STATE>0x00000000</STATE><STATENAME>OK</STATENAME></RESP></LOGIN><SCLEnabled>0</SCLEnabled></drac>
    # - Failed login (with newlines in between the second item:
    #   - HTTP/1.1 200 OK
    #   - <?xml version="1.0" encoding="UTF-8"?><?xml-stylesheet type="text/xsl" href="/cgi/locale/login_en.xsl" media="screen"?><drac>
    #     <privilege racPrivilege="0" login="0" cfg="0" cfguser="0" clearlog="0" servercontrol="0" console="0" vmedia="0" testalert="0" debug="0" />
    #     <CARD_IP>redacted</CARD_IP><OEM>0</OEM><MSG>0x0</MSG><LANG>en</LANG>
    #     <LOGIN><RESP><RC>0x140004</RC><SID>0</SID><STATE>0x00000000</STATE><STATENAME>OK</STATENAME></RESP></LOGIN><SCLEnabled>0</SCLEnabled></drac>
    login_fail = "<RC>0x140004</RC>";
  }

  else if(cpe =~ "^cpe:/a:dell:idrac6" || cpe =~ "^cpe:/a:dell:idrac7" ||
          cpe =~ "^cpe:/a:dell:idrac8") {
    urls = make_list("/data/login", "/Applications/dellUI/RPC/WEBSES/create.asp");
    posts = make_list("user=" + user + "&password=" + pass, "WEBVAR_PASSWORD=" + pass + "&WEBVAR_USERNAME=" + user + "&WEBVAR_ISCMCLOGIN=0");
    # - Successful login on /data/login (iDRAC6 through iDRAC8):
    #   - HTTP/1.1 200 OK
    #   - <?xml version="1.0" encoding="UTF-8"?> <root> <status>ok</status> <authResult>0</authResult> <forwardUrl>index.html?ST1=redacted,ST2=redacted</forwardUrl> </root>
    #   or:
    #   - <?xml version="1.0" encoding="UTF-8"?> <root> <status>ok</status> <authResult>0</authResult> <forwardUrl>index.html</forwardUrl> </root>
    # - Failed login on /data/login (iDRAC6 through iDRAC8):
    #   - HTTP/1.1 200 OK
    #   - <?xml version="1.0" encoding="UTF-8"?> <root> <status>ok</status> <authResult>1</authResult> <blockingTime>0</blockingTime>  <forwardUrl>index.html</forwardUrl>  <errorMsg></errorMsg></root>
    #   or:
    #   - <?xml version="1.0" encoding="UTF-8"?> <root> <status>ok</status> <authResult>99</authResult> <forwardUrl>index.html</forwardUrl>  <errorMsg></errorMsg></root>
    #   or:
    #   - <?xml version="1.0" encoding="UTF-8"?> <root> <status>ok</status> <authResult>1</authResult> <forwardUrl>index.html</forwardUrl>  <errorMsg></errorMsg></root>
    login_success = make_list("<authResult>0</authResult>", "'USERNAME' : 'root'");
  }

  else if(cpe =~ "^cpe:/a:dell:idrac9" || cpe =~ "^cpe:/a:dell:idrac$") {
    urls = make_list("/sysmgmt/2015/bmc/session");
    # nb: Special case as we need to pass the creds as headers here.
    posts = make_list("empty");
    # - Successful login:
    #   - HTTP/1.1 200 or HTTP/1.1 201
    #   - {"authResult":0}
    #   - Variable-AUTHNZ_USER: root
    # - Failed login:
    #   - HTTP/1.1 401 Unauthorized
    #   - {"authResult":1,"blockingTime":0}
    login_success = make_list('"authResult":0');
  }

  else {
    return FALSE;
  }

  foreach url(urls) {

    foreach post(posts) {

      buf = FALSE;

      sleep(1);

      if(post == "empty") {
        post = NULL;
        accept_header = NULL;
        # nb: Credentials needs to be put around "" so that the passed header looks like e.g.:
        # User: "root"
        # Password: "calvin"
        headers = make_array("User", '"' + user + '"', "Password", '"' + pass + '"');
      } else {
        accept_header = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        headers = make_array("Content-Type", "application/x-www-form-urlencoded");
      }

      req = http_post_put_req(port:port, url:url, data:post, accept_header:accept_header, add_headers:headers);
      buf = http_send_recv(port:port, data:req);
      if(!buf || buf !~ "^HTTP/1\.[01] 20[01]")
        continue;

      if(login_fail && login_fail >!< buf)
        return make_list(url, "HTTP 200/201 status code and not matching response: " + login_fail);

      if(login_success) {
        foreach ls(login_success) {
          if(ls >< buf) {
            return make_list(url, "HTTP 200/201 status code and matching response: " + ls);
          }
        }
      }
    }
  }
  return FALSE;
}

# nb: Using the "cpe:/a:dell:idrac" here because we want to "fallback" to a default check (currently
# iDRAC9) if no generation was extracted.
cpe_list = make_list(
  "cpe:/a:dell:idrac4", "cpe:/a:dell:idrac5", "cpe:/a:dell:idrac6", "cpe:/a:dell:idrac7",
  "cpe:/a:dell:idrac8", "cpe:/a:dell:idrac9", "cpe:/a:dell:idrac"
);

if(!infos = get_app_port_from_list(cpe_list:cpe_list, service:"www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if(!get_app_location(cpe:cpe, port:port, nofork:TRUE))
  exit(0);

if(info = check_iDRAC_default_login(cpe:cpe, port:port)) {
  report = "It was possible to login with username 'root' and password 'calvin'.";
  report += '\n\n' + http_report_vuln_url(port:port, url:info[0]);
  report += '\nResult:         ' + info[1];
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
