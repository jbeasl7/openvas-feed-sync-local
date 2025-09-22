# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oscmax:oscmax";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805566");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2012-1665", "CVE-2012-1664");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-05-27 13:56:19 +0530 (Wed, 27 May 2015)");
  script_name("osCMax e-commerce/shopping-cart Multiple Vulnerabilities");

  script_tag(name:"summary", value:"osCMax is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Input passed via 'username' POST parameter to /admin/login.php script,
  'pageTitle' GET parameter to /admin/new_attributes_include.php script, the
  'sb_id', 'sb_key', 'gc_id', 'gc_key' and 'path' POST parameters to
  /admin/htaccess.php script, the 'title' GET parameter to
  /admin/information_form.php script, the 'search' GET parameter to
  /admin/xsell.php script, the 'gross' and 'max' GET parameters to
  /admin/stats_products_purchased.php script, the 'status' GET parameter to
  /admin/stats_monthly_sales.php script, the 'sorted' GET parameter to
  /admin/stats_customers.php script, the 'information_id' GET parameter to
  /admin/information_manager.php script, the 'zID' GET parameter to
  /admin/geo_zones.php script, the 'current_product_id' and 'cPath' GET parameters
  to /admin/new_attributes_include.php script is not properly sanitised before
  being returned to the user.

  - Input passed via the 'status' GET parameter to /admin/stats_monthly_sales.php
  script, the 'country' POST parameter to /admin/create_account_process.php script,
  the 'username' POST parameter to /admin/login.php script is not properly sanitised
  before being used in SQL query.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database, allowing
  for the manipulation or disclosure of arbitrary data and also create a specially
  crafted URL that would execute arbitrary script code in a user's browser within
  the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"osCMax before version 2.5.1");

  script_tag(name:"solution", value:"Upgrade to osCMax version 2.5.1 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23081");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52886");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-04/0021.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_oscmax_detect.nasl");
  script_mandatory_keys("oscmax/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.oscmax.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!ePort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:ePort)){
  exit(0);
}

host = http_host_name(port:ePort);

url = dir + "/admin/login.php?action=process";

postData = "username='<script>alert(document.cookie);</script>&password" +
           "='<script>alert(document.cookie);</script>";

sndReq =  string('POST ', url, ' HTTP/1.1\r\n',
                 'Host: ', host, '\r\n',
                 'Content-Type: application/x-www-form-urlencoded\r\n',
                 'Content-Length: ', strlen(postData), '\r\n\r\n',
                  postData);
rcvRes = http_keepalive_send_recv(port:ePort, data:sndReq);

if(rcvRes =~ "HTTP/1\.. 200" && "<script>alert(document.cookie);</script>" >< rcvRes
          && "Wrong Username" >< rcvRes && "error" >< rcvRes)
{
  security_message(port: ePort);
  exit(0);
}

exit(99);
