# SPDX-FileCopyrightText: 2003 StrongHoldNet
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:caucho:resin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11930");
  script_version("2023-06-16T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-06-16 05:06:18 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Caucho Resin '/caucho-status' Accessible (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2003 StrongHoldNet");
  script_family("Web Servers");
  script_dependencies("gb_caucho_resin_http_detect.nasl");
  script_mandatory_keys("caucho/resin/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.caucho.com/resin-4.0/admin/starting-resin-apache.xtp#caucho-status");

  script_tag(name:"summary", value:"The remote Caucho Resin installation is exposing the
  /caucho-status endpoint.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Requesting the URI /caucho-status gives information about the
  currently running Caucho Resin Java servlet container.");

  script_tag(name:"solution", value:"If you don't use this feature, set the content of the
  '<caucho-status>' element to 'false' in the resin.conf file.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/caucho-status";
res = http_get_cache(item: url, port: port);
if (!res)
  exit(0);

# <html><title>Status : Caucho Servlet Engine</title>
# <h1>Status : Caucho Servlet Engine</h1>
#
# nb: The initial version of this VT had only checked for:
# if("<title>Status : Caucho Servlet Engine" >< r && "%cpu/thread" >< r)
# But as at least 3.1.x versions seems to not include "%cpu/thread" anymore a second pattern was
# added. Furthermore we're not using a trailing "</(title|h1)>" because we don't know (based on the
# previously used pattern) if some installations had some text included afterwards or similar.
if (egrep(string: res, pattern: "<(title|h1)>Status : Caucho Servlet Engine", icase: FALSE) &&
    # <b>Source:</b> Resin-ETag
    # <td>/resin-admin<td>*.jsp</tr>
    # <hr><em>Resin/3.1.10<em></body></html>
    res =~ "(%cpu/thread|Resin)") {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
