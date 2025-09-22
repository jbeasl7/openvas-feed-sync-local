# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902384");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WordPress WPtouch URL Redirection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17423");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102451/wptouch-redirect.txt");

  script_tag(name:"summary", value:"The WordPress plugin 'WPtouch' is prone to an URL redirection vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to an improper
  validation of user supplied input data via 'wptouch_redirect' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to redirect to his choice of malicious site via the trusted
  vulnerable url.");

  script_tag(name:"affected", value:"WordPress WPtouch Plugin Version 1.9.27 and 1.9.28.");

  script_tag(name:"solution", value:"No known solution was made available for at least
  one year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/wptouch/admin-css/wptouch-admin.css";

if(http_vuln_check(port:port, url:url, check_header:TRUE, usecache:TRUE, pattern:"wptouch-head-title", extra_check:make_list("wptouch-pages", "wptouch-head-links"))) {

  url = dir + "/?wptouch_view=normal&wptouch_redirect=" + dir + "/readme.html";

  req = http_get(item:url, port:port);
  res = http_send_recv(port:port, data:req);

  if(egrep(pattern:"^HTTP/1\.[01] 302", string:res) &&
     egrep(pattern:"^Location:.*/readme\.html", string:res) &&
     egrep(pattern:"^Set-Cookie: wptouch_switch_toggle=normal", string:res)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
