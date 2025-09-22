# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:solarwinds:storage_resource_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809427");
  script_version("2025-06-25T05:41:02+0000");
  script_cve_id("CVE-2016-4350");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-16 13:52:00 +0000 (Mon, 16 May 2016)");
  script_tag(name:"creation_date", value:"2016-10-03 15:36:59 +0530 (Mon, 03 Oct 2016)");
  script_name("SolarWinds Storage Resource Monitor (SRM) < 6.2.3 Multiple SQLi Vulnerabilities");

  script_tag(name:"summary", value:"SolarWinds Storage Resource Monitor (SRM) is prone to multiple
  SQL injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws exist due to Web Services web server does not
  validate state parameter properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary SQL commands.");

  script_tag(name:"affected", value:"SolarWinds SRM prior to version 6.2.3.");

  script_tag(name:"solution", value:"Update to version 6.2.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_probe");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-253");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-259");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-262");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210123130817/http://www.securityfocus.com/bid/89557");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_solarwinds_storage_resource_monitor_detect.nasl");
  script_mandatory_keys("solarwinds/srm/http/detected");
  script_require_ports("Services/www", 9000);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

data = "loginState=checkLogin&loginName=admin&password=";

req = http_post_put_req(port:port,
                        url:"/LoginServlet",
                        data:data,
                        accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        add_headers:make_array("Content-Type", "application/x-www-form-urlencoded") );
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf =~ "^HTTP/1\.[01] 200" && "SolarWinds - Storage Manager" >< buf) {

  cookie = eregmatch(pattern:"Set-Cookie: ([0-9a-zA-Z=]+);", string:buf);
  if(!cookie[1])
    exit(0);

  url = "/DuplicateFilesServlet?fileName=%27SQL-INJECTION-TEST";

  if(http_vuln_check(port:port, url:url, check_header:TRUE, cookie:cookie[1],
                     pattern:"SQL-INJECTION-TEST",
                     extra_check:make_list(">Enterprise Report<", ">Storage Manager<"))) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }

  exit(99);
}

exit(0);
