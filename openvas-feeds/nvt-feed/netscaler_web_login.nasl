# SPDX-FileCopyrightText: 2008 nnposter
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80025");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Citrix NetScaler Web Management Login (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 nnposter");
  script_family("Service detection");
  script_dependencies("logins.nasl", "gb_citrix_netscaler_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("citrix/netscaler/http/detected", "http/login");

  script_tag(name:"summary", value:"The scanner successfully logged into the remote Citrix NetScaler
  web management interface using the supplied credentials and stored the authentication cookie for
  later use.");

  exit(0);
}

include("url_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if (!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/ws/login.pl?" +
      "username=" + urlencode(str:get_kb_item("http/login")) +
      "&password=" + urlencode(str:get_kb_item("http/password")) +
      "&appselect=stat";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, embedded:TRUE);
if (!res)
  exit(0);

cookie = egrep(pattern:"^Set-Cookie:", string:res, icase:TRUE);
if (!cookie)
  exit(0);

cookie = ereg_replace(string:cookie, pattern:'^Set-', replace:" ", icase:TRUE);
cookie = ereg_replace(string:cookie, pattern:';[^\r\n]*', replace:";", icase:TRUE);
cookie = ereg_replace(string:cookie, pattern:'\r\nSet-Cookie: *', replace:" ", icase:TRUE);
cookie = ereg_replace(string:cookie, pattern:'; *(\r\n)', replace:"\1", icase:TRUE);
if (!cookie || cookie !~ " ns1=.* ns2=")
  exit(0);

set_kb_item(name:"/tmp/http/auth/" + port, value:cookie);
log_message(port:port);

exit(0);
