# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opencart:opencart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804161");
  script_version("2024-07-12T15:38:44+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-12 15:38:44 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-12-09 19:52:35 +0530 (Mon, 09 Dec 2013)");

  script_name("OpenCart <= 1.5.6 Multiple Vulnerabilities (Dec 2013)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_opencart_http_detect.nasl");
  script_mandatory_keys("opencart/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"OpenCart is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws are due to:

  - Input passed via the 'zone_id' POST parameter to index.php is not properly sanitised before
  being returned to the user.

  - Insufficient authorization accessing 'system/logs/error.txt' which displays the full
  installation path within error messages.

  - Insufficient validity checks to verify the HTTP requests made by user.");

  script_tag(name:"affected", value:"OpenCart version 1.5.6 is known to be affected. Other versions
  may also be affected.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute
  arbitrary HTML or script code, discloses the software's installation path resulting in a loss of
  confidentiality.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53036");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64162");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Dec/29");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/53036");
  script_xref(name:"URL", value:"http://www.garda.ir/Opencart_Multiple_Vulnerabilities.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/system/logs/error.txt";

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"PHP Notice\s*:\s*Undefined index:")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
