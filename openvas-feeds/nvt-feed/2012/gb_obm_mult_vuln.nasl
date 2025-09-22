# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803027");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-09-18 11:33:54 +0530 (Tue, 18 Sep 2012)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2011-5141", "CVE-2011-5142", "CVE-2011-5143", "CVE-2011-5144",
                "CVE-2011-5145");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Open Business Management <= 2.4.0-rc13 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Open Business Management is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple vulnerabilities due to:

  - Improper access restrictions to the 'test.php' script allowing attackers to obtain
  configuration information via a direct request to test.php, which calls the phpinfo function.

  - Input passed via the 'sel_domain_id' and 'action' parameters to 'obm.php' is not properly
  sanitised before being used in SQL queries.

  - Input passed via the 'tf_user' parameter to group/group_index.php and 'tf_name',
  'tf_delegation', and 'tf_ip' parameters to host/host_index.php is not properly sanitised before
  being used in SQL queries.

  - Input passed to the 'tf_name', 'tf_delegation', and 'tf_ip' parameters in index.php, 'login'
  parameter in obm.php, and 'tf_user' parameter in group/group_index.php is not properly sanitised
  before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to cause SQL
  injection attack, gain sensitive information and execute arbitrary HTML and script code in a
  user's browser session in the context of a vulnerable site.");

  script_tag(name:"affected", value:"Open Business Management (OBM) version 2.4.0-rc13 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47139");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51153");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71924");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23060");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/obm", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/obm.php");
  if (!res || res !~ "^HTTP/1\.[01] 200" || (res !~ "<title>.* OBM" && res !~ "OBM\.org"))
    continue;

  url = dir + "/test.php";

  if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern:"<title>phpinfo\(\)",
                      extra_check: make_list(">System <", ">Configuration<", ">PHP Core<"))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
