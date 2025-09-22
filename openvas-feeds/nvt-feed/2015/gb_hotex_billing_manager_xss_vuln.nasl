# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805371");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-04-27 10:13:24 +0530 (Mon, 27 Apr 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2015-3319", "CVE-2015-2781");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Hotspot Express hotEx Billing Manager <= 73 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Hotspot Express hotEx Billing Manager is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Input passed via the 'reply' parameter to 'hotspotlogin.cgi' is not properly sanitised before
  being returned to the user.

  - HTTPOnly flag is not included in Set-Cookie header, which makes it easier for remote attackers
  to obtain potentially sensitive information via script access to this cookie");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a users browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Hotspot Express hotEx Billing Manager version 73 and probably
  prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Apr/18");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535186/100/0/threaded");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131297/HotExBilling-Manager-73-Cross-Site-Scripting.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  url = dir + "/hotspotlogin.cgi?res=failed&reply=1";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("> Login<" >!< res || "hotspot_popup" >!< res)
    continue;

  url = "/cgi-bin/hotspotlogin.cgi?res=failed&reply=" +
        "<script>alert%28document.cookie%29<%2fscript>" +
        "%2c%20Invalid%20username%20or%20Password";

  if (http_vuln_check(port: port, url: url, check_header: TRUE, extra_check: "> Login<",
                      pattern: "_script_alert\(document\.cookie\)_/script_")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
