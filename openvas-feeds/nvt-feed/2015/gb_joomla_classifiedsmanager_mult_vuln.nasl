# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805271");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-1478", "CVE-2015-1477");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-02-10 15:15:51 +0530 (Tue, 10 Feb 2015)");

  script_name("Joomla Component CMSJunkie J-ClassifiedsManager Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Joomla component CMSJunkie J-ClassifiedsManager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple errors exist as,

  - Input passed via the 'view' parameter to /classifieds script is not validated before returning it to users.

  - Input passed via the 'id' parameter to /classifieds/offerring-ads script is not properly sanitized before
returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to inject or manipulate SQL queries in the back-end database, allowing for the
  manipulation or disclosure of arbitrary data, and also execute arbitrary script
  code in a user's browser session within the trust relationship between their
  browser and the server.");

  script_tag(name:"affected", value:"Joomla CMSJunkie J-ClassifiedsManager");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35911");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130093");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/jclassifiedsmanager/classifieds/offerring-ads?controller=displa'
          + 'yads&view=displayads&task=viewad&id="SQL-INJECTION-TEST';

if(http_vuln_check(port:http_port, url:url, check_header:FALSE, pattern:"You have an error in your SQL syntax",
                   extra_check: make_list("SQL-INJECTION-TEST", "classifiedsmanager")))
{
  report = http_report_vuln_url(port: http_port, url: url);
  security_message(port: http_port, data: report);
  exit(0);
}

exit(99);
