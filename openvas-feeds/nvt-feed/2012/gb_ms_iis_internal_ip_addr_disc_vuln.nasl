# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902796");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-02-23 15:45:49 +0530 (Thu, 23 Feb 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Microsoft IIS IP Address/Internal Network Name Disclosure Vulnerability - Active Check");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/834141/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3159");
  script_xref(name:"URL", value:"http://support.microsoft.com/default.aspx?scid=KB;EN-US;Q218180");
  script_xref(name:"URL", value:"http://www.juniper.net/security/auto/vulnerabilities/vuln3159.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl", "no404.nasl",
                      "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  internal IP address or internal network name, which could assist in further attacks against the
  target host.");

  script_tag(name:"insight", value:"The flaw is due to an error while processing 'GET' request. When
  MS IIS receives a GET request without a host header, the Web server will reveal the IP address of
  the server in the content-location field or the location field in the TCP header in the
  response.");

  script_tag(name:"solution", value:"Apply the hotfix for IIS 6.0.");

  script_tag(name:"summary", value:"Microsoft Internet Information Services (IIS) Webserver is
  prone to an IP address disclosure vulnerability.");

  script_tag(name:"affected", value:"Microsoft IIS version 4.0, 5.0, 5.1 and 6.0.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

host = http_host_name(dont_add_port:TRUE);

foreach dir( make_list_unique("/", "/scripts", "/admin", "/webdav", http_cgi_dirs(port:port))) {
  ip = string("http://", host, dir);

  sndReq = string("GET ", dir, " HTTP/1.0 \r\n\r\n");
  rcvRes = http_send_recv(port:port, data:sndReq);

  pattern = string("Location: ", ip);

  if(rcvRes && pattern >< rcvRes &&
     egrep(pattern:"^HTTP/1\.[01] 302 Object Moved", string:rcvRes)) {
    report = http_report_vuln_url(port:port, url:dir);
    security_message(port:port, data:report);
    exit(0);
  }
}
