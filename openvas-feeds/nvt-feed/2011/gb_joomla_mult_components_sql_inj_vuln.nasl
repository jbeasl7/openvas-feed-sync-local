# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802196");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2010-4927", "CVE-2010-4928", "CVE-2010-4929", "CVE-2010-4937",
                "CVE-2010-4945", "CVE-2010-4902", "CVE-2010-4865", "CVE-2010-4904");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-11-03 15:42:01 +0200 (Thu, 03 Nov 2011)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla Multiple Components SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/40932");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33254");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42334");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42986");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43014");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43319");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43415");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43605");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41322");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62151");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14530/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14596/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14530/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15040/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15157/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14902/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/92305/joomlacamelcitydb2-sql.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105704/joomlasgicatalog-sql.txt");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Joomla Joostina component, Joomla sgicatalog component, Joomla Amblog
  component version 1.0, Joomla Clantools Component version 1.2.3, Joomla CamelcityDB component version 2.2, Joomla
  Clantools Component version 1.2.3, Joomla Restaurant Guide component version 1.0.0, Joomla Aardvertiser Component
  versions 2.1 and 2.1.1.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"solution", value:"Update the components.");

  script_tag(name:"summary", value:"Joomla with multiple components is prone to SQL injection vulnerabilities.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

pages = make_list("/index.php?option=com_restaurantguide&view=country&id='&Itemid=69",
                  "/index.php?option=com_ezautos&Itemid=49&id=1&task=helpers&firstCode='",
                  "/index.php?option=com_amblog&task=editsave&articleid='",
                  "/index.php?option=com_camelcitydb2&view=all&Itemid=15",
                  "/index.php?option=com_jeguestbook&view=item_detail&d_itemid='",
                  "/index.php?option=com_clantools&squad='",
                  "/index.php?option=com_sgicatalog&task=view&lang=en&id='",
                  "/index.php?option=com_aardvertiser&amp;cat_name='x+AND+'1'='1&amp;task=view");

foreach page (pages) {
  url = dir + page;
  if (http_vuln_check(port: port, url: url,
                      pattern: "<b>Warning</b>:  Invalid argument supplied for foreach\(\)") ||
      http_vuln_check(port: port, url: url, pattern:"You have an error in your SQL syntax;")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
