# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800304");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2008-11-11 09:00:11 +0100 (Tue, 11 Nov 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-4784");
  script_name("aflog Cookie-Based Authentication Bypass Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31894");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Exploitation will allow an attacker to gain administrative access and bypass
  authentication.");

  script_tag(name:"affected", value:"aflog versions 1.01 and prior on all running platform");

  script_tag(name:"insight", value:"The flaw is due to inadequacy in verifying user-supplied input used
  for cookie-based authentication by setting the aflog_auth_a cookie to
  'A' or 'O' in edit_delete.php, edit_cat.php, edit_lock.php, and edit_form.php.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"aflog is prone to an cookie-based authentication bypass vulnerability.");

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

foreach path (make_list_unique("/aflog", http_cgi_dirs(port:port)))
{

  if(path == "/") path = "";

  rcvRes = http_get_cache(item: path + "/Readme.txt", port:port);
  if(egrep(pattern:"Aflog v1.01", string:rcvRes) &&
     egrep(pattern:"^HTTP/1\.[01] 200", string:rcvRes))
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
