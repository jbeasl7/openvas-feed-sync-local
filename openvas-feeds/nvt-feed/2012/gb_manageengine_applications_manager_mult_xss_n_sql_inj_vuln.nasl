# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_applications_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802424");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-02-16 15:09:43 +0530 (Thu, 16 Feb 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-1062", "CVE-2012-1063");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_name("ManageEngine Applications Manager 9.x, 10.x Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_appli_manager_detect.nasl");
  script_mandatory_keys("zohocorp/manageengine_applications_manager/detected");
  script_require_ports("Services/www", 9090);

  script_tag(name:"summary", value:"ManageEngine Applications Manager is prone to multiple
  cross-site scripting (XSS) and SQL injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws are due to an input passed to the

  - 'query', 'selectedNetwork', 'network', and 'group' parameters in various scripts is not
  properly sanitised before being returned to the user.

  - 'viewId' parameter to fault/AlarmView.do and 'period' parameter to showHistoryData.do is not
  properly sanitised before being used in SQL queries.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site and compromise
  the application, access or modify data, or exploit latent vulnerabilities in the underlying
  database.");

  script_tag(name:"affected", value:"ManageEngine Applications Manager version 9.x and 10.x.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47724");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51796");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72830");
  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=115");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/109238/VL-115.txt");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url =  dir + "/jsp/PopUp_Graph.jsp?restype=QueryMonitor&resids=&attids='&attName=" +
      "><script>alert(document.cookie)</script>";

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: "<script>alert\(document\.cookie\)</script>")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
