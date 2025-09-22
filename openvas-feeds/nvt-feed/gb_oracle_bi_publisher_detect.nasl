# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809732");
  script_version("2020-12-16T09:35:48+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-12-16 09:35:48 +0000 (Wed, 16 Dec 2020)");
  script_tag(name:"creation_date", value:"2016-11-25 16:04:15 +0530 (Fri, 25 Nov 2016)");
  script_name("Oracle BI Publisher Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9704);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Oracle BI Publisher.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:9704);

res = http_get_cache(item:"/xmlpserver/login.jsp", port:port);
if(!res || res !~ "^HTTP/1\.[01] 200")
  exit(0);

# <title>Oracle BI Publisher Enterprise Login</title>
# nb: Unclear if other / older version had e.g. no "Enterprise"
# so the check below is trying various patterns.
if(("<title>Oracle BI Publisher" >< res && "Login</title>" >< res) ||
   'class="Copyright">Oracle BI Publisher' >< res || 'name="Generator" content="Oracle BI Publisher' >< res) {

  version = "unknown";
  extra = "";

  # <meta name="Generator" content="Oracle BI Publisher 11.1.1.6.0 (build# 20111224.0351 on Sat Dec 24 03:59:54 PST 2011)"/>
  # <meta name="Generator" content="Oracle BI Publisher 10.1.3.4.2 (build# 1350 on Thu Sep 19 19:47:45 SAST 2013)"/>
  # <meta name="Generator" content="Oracle BI Publisher 12.2.1.3.0 (build# 20191016.2041 on Wed Oct 16 20:45:50 COT 2019)"/>
  vers = eregmatch(pattern:'content="Oracle BI Publisher ([0-9.]+)( .build# ([0-9.]+))?', string:res);
  if(vers[1])
    version = vers[1];

  if(vers[3])
    extra += "Build: " + vers[3];

  if(version == "unknown") {
    # <span class="Copyright">Oracle BI Publisher 11.1.1.6.0 </span>&#160;<br/>
    # <span class="Copyright">Oracle BI Publisher 12.2.1.3.0 </span>&#160;<br/>
    # <span class="copyright">Oracle BI Publisher 10.1.3.4.2 </span>&nbsp;<div></div>
    vers = eregmatch(pattern:'"Copyright">Oracle BI Publisher ([0-9.]+)', string:res, icase:TRUE);
    if(vers[1])
      version = vers[1];
  }

  set_kb_item(name:"oracle/bi_publisher/detected", value:TRUE);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:oracle:business_intelligence_publisher:");
  if(!cpe)
    cpe = "cpe:/a:oracle:business_intelligence_publisher";

  register_product(cpe:cpe, location:"/", port:port, service:"www");
  log_message(data:build_detection_report(app:"Oracle BI Publisher",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          extra:extra,
                                          concluded:vers[0]),
                                          port:port);
}

exit(0);
