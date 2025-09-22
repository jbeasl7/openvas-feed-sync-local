# SPDX-FileCopyrightText: 2004 Westpoint Limited and Corsaire Limited
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:verity:ultraseek";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12300");
  script_version("2025-07-23T05:44:58+0000");
  script_tag(name:"last_modification", value:"2025-07-23 05:44:58 +0000 (Wed, 23 Jul 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2004-0050");
  script_name("Infoseek / Verity Ultraseek < 5.2.2 Physical Path Disclosure (Jan 2004) - Active Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Westpoint Limited and Corsaire Limited");
  script_family("Web application abuses");
  script_dependencies("gb_ultraseek_http_detect.nasl");
  script_require_ports("Services/www", 8765);
  script_mandatory_keys("ultraseek/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20061018032433/http://www.corsaire.com/advisories/c040113-001.txt");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210128192317/http://www.securityfocus.com/bid/10275");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121160646/http://www.securityfocus.com/bid/8050");

  script_tag(name:"summary", value:"Infoseek / Verity Ultraseek (formerly Inktomi Search) is prone
  to a physical path disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Certain requests using MS-DOS special file names such as nul can
  cause a python error. The error message contains sensitive information such as the physical path
  of the webroot. This information may be useful to an attacker.");

  script_tag(name:"solution", value:"Update to version 5.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/nul";
req = http_get(port:port, item: url);
res = http_keepalive_send_recv(port: port, data: req);
if (!res)
  exit(0);

if ("httpsrvr.py:1033" >!< res || "500 Internal Server Error" >!< res)
  exit(0);

w = egrep(string: res, pattern: "directory");
if (w) {
  webroot = ereg_replace(string: w, pattern: "^.*'(.*)'.*$", replace: "\1");
  if (webroot == w)
    exit(0);

  report = http_report_vuln_url(port: port, url: url);
  report += '\n\nThe remote web root is: ' + w;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
