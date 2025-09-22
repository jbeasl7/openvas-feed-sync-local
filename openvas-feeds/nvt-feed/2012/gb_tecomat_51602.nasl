# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_xref(name:"URL", value:"https://web.archive.org/web/20210214011335/https://www.securityfocus.com/bid/51602/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20120828235418/http://dsecrg.com/pages/vul/show.php?id=407");

  script_oid("1.3.6.1.4.1.25623.1.0.103397");
  script_version("2025-01-31T05:37:27+0000");

  script_name("Tecomat Foxtrot Default Credentials (HTTP)");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-01-24 10:17:53 +0100 (Tue, 24 Jan 2012)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("softplc/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Tecomat Foxtrot is using known default credentials for the HTTP
  login.");

  script_tag(name:"vuldetect", value:"Tries to login via HTTP using known default credentials.");

  script_tag(name:"impact", value:"Successful attacks can allow an attacker to gain access to the
  affected application using the default authentication credentials.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

host = http_host_name(port:port);

url = "/syswww/login.xml";
buf = http_get_cache(item:url, port:port);

if(!buf || "SoftPLC" >!< buf)
  exit(0);

cookie = eregmatch(string:buf, pattern:"[Ss]et-[Cc]ookie\s*:\s*SoftPLC=([^;]+)");
if(isnull(cookie[1]))
  exit(0);

c = cookie[1];

for(i = 9; i >= 0; i--) {

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Connection: keep-alive\r\n",
               "Referer: http://", host, url, "\r\n",
               "Cookie: SoftPLC=", c, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: 10\r\n",
               "\r\n",
               "USER=", i, "&PASS=", i, "\r\n\r\n");

  buf = http_keepalive_send_recv(port:port, data:req);
  search = string("[Ll]ocation\s*:\s*https?://", host, "/index\.xml");

  if(egrep(string:buf, pattern:search)) {
    report = string("It was possible to login with the following credentials\n\nURL:User:Password\n\n", url, ":", i, ":", i, "\n");
    security_message(port:port, data:report);
    exit(0);
  }
  sleep(1);
}

exit(99);
