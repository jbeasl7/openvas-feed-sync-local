# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:finderview:finderview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808097");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2016-06-27 14:33:21 +0530 (Mon, 27 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("FinderView Multiple Vulnerabilities");

  script_tag(name:"summary", value:"FinderView is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an
  insufficient validation of user supplied input via GET parameter 'callback'
  to 'api.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to view directory and to cause cross site scripting and steal the
  cookie of other active sessions.");

  script_tag(name:"affected", value:"FinderView version 0.1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40011");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_finderview_detect.nasl");
  script_mandatory_keys("FinderView/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!find_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:find_port)){
  exit(0);
}

if(dir == "/") dir = "";

url =  dir + "/api.php?callback=<script>alert(document.cookie)<%2fscript>";

if(http_vuln_check(port:find_port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\)</script>",
                   extra_check:"README.md"))
{
  report = http_report_vuln_url(port:find_port, url:url);
  security_message(port:find_port, data:report);
  exit(0);
}
