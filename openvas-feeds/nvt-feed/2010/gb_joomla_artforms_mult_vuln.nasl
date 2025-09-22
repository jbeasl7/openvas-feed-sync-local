# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902219");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2010-2846", "CVE-2010-2848", "CVE-2010-2847");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Joomla! ArtForms Component Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41457");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60161");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60160");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14263/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1007-exploits/joomlaartforms-sqltraversalxss.txt");

  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to insert arbitrary
  HTML or to execute arbitrary SQL commands or to read arbitrary files.");

  script_tag(name:"affected", value:"Joomla ArtForms version 2.1b7.2 RC2 and prior.");

  script_tag(name:"insight", value:"The flaws are due to:

  - Error in the 'ArtForms' (com_artforms) component, allows remote attackers to inject arbitrary
  web script or HTML via the 'afmsg' parameter to 'index.php'.

  - Directory traversal error in 'assets/captcha/includes/alikon/playcode.php' in the InterJoomla
  'ArtForms' (com_artforms) component, allows remote attackers to read arbitrary files via a .. (dot
  dot) in the 'l' parameter.

  - Multiple SQL injection errors in the 'ArtForms' (com_artforms) component, allows remote
  attackers to execute arbitrary SQL commands via the 'viewform' parameter in a 'ferforms' and
  'tferforms' action to 'index.php', and the 'id' parameter in a 'vferforms' action to 'index.php'.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"Joomla is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

req = http_get(item:dir + "/index.php?option=com_artforms", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res || "ArtForms" >!< res)
  exit(0);

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = dir + "/components/com_artforms/assets/captcha/includes/alikon/playcode.php?l=../../../../../../../../../../../../" + file + "%00";

  if(http_vuln_check(port:port, url:url, pattern:pattern, check_header:TRUE)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

ver = eregmatch(string:res, pattern:"v. (([0-9.]+)(([a-zA-Z])?([0-9.]+)?.?([a-zA-Z0-9.]+))?)");
if(!isnull(ver[1]))
  compVer = ereg_replace(pattern:"([a-z])|( )", string:ver[1], replace:".");

if(compVer && version_is_less_equal(version:compVer, test_version:"2.1.7.2.RC2")) {
  report = report_fixed_ver(installed_version:compVer, fixed_version:"None");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
