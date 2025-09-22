# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802387");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-02-01 13:14:14 +0530 (Wed, 01 Feb 2012)");
  script_name("SolGens E-Commerce 'cid' And 'pid' Parameters SQLi Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108947/solgensecommerce-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform SQL injection
  attack and gain sensitive information.");

  script_tag(name:"affected", value:"SolGens E-Commerce");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input
  sent via the 'cid' and 'pid' parameters to 'product_detail.php',
  'category_products.php' and 'order_product.php' scripts, which allows
  attackers to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"SolGens E-Commerce is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/solgens", "/SolGens", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:port);

  if(egrep(pattern:">.?SolGens", string:rcvRes))
  {
    url = dir + "/product_detail.php?pid='";

    if(http_vuln_check(port:port, url:url, pattern:">Warning<.*supplied " +
      "argument is not a valid MySQL result resource in.*product_detail.php"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
