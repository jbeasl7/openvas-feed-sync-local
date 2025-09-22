# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dorg:dorg";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806697");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2016-04-06 16:25:02 +0530 (Wed, 06 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Disc Organization System (DORG) Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Disc Organization System (DORG) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET method
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to improper
  sanitization of input to 'search' and 'q' parameters in results.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session,
  and inject or manipulate SQL queries in the back-end database, allowing
  for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Disc Organization System version 1.1.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39580");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Mar/72");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_dorg_detect.nasl");
  script_mandatory_keys("DORG/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!dorgPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:dorgPort)){
  exit(0);
}

url = dir + "/results.php?q=%27%22%3C%2fscript%3E%3Cscript%3Ealert%28docum" +
            "ent.cookie%29%3C%2fscript%3E&search=Search&type=3";

if(http_vuln_check(port:dorgPort, url:url, check_header:TRUE,
       pattern:"<script>alert\(document.cookie\)</script>",
       extra_check: make_list("DORG Search results</title", "dorg.png")))
{
  report = http_report_vuln_url( port:dorgPort, url:url);
  security_message(port:dorgPort, data:report);
  exit(0);
}
