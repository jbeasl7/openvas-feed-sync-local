# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103507");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-07-03 10:23:40 +0200 (Tue, 03 Jul 2012)");
  script_name("Microsoft IIS Authentication Bypass and Source Code Disclosure Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_microsoft_iis_http_detect.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53906");

  script_tag(name:"summary", value:"Microsoft IIS is prone to an authentication-bypass vulnerability and a
  source-code disclosure vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"insight", value:"An attacker can exploit these vulnerabilities to gain unauthorized
  access to password-protected resources and view the source code of files in the context of the server
  process. This may aid in further attacks.");

  script_tag(name:"affected", value:"Microsoft IIS 6.0 and 7.5. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

host = http_host_name(dont_add_port:TRUE );

auth_req = http_get_kb_auth_required(port:port, host:host);
if(!auth_req)
  exit(0);

protected = make_list(auth_req);

files = make_list("/index.php", "/admin.php", "/login.php", "/default.asp", "/login.asp");

asp_ia = ":$i30:$INDEX_ALLOCATION";
php_ia = "::$INDEX_ALLOCATION";

x = 0;

foreach p (protected) {

  x++;

  if(ereg(pattern:"/$", string:p)) {

    p = ereg_replace(string:p, pattern:"/$", replace:"");

    foreach file (files) {

      if(".asp" >< file) {
        ia = asp_ia;
      } else {
        ia = php_ia;
      }

      url = p + file;

      buf = http_get_cache(item:url, port:port);
      if(!buf || buf !~ "^HTTP/1\.[01] 401")
        continue;

      url =  p + ia + file;

      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

      if(buf =~ "^HTTP/1\.[01] 200") {
        report = http_report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
  if(x > 5) {
    exit(0);
  }
}

exit(99);
