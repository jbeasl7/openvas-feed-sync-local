# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800817");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2262");
  script_name("AjaxPortal 'di.php' File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504618/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ajaxportal_detect.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ajaxportal/detected");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker to execute
  arbitrary PHP code via a URL in the pathtoserverdata parameter.");

  script_tag(name:"affected", value:"MyioSoft, AjaxPortal version 3.0.");

  script_tag(name:"insight", value:"The flaw is due to error in the 'pathtoserverdata' parameter in
  install/di.php and it can exploited to cause PHP remote file inclusion.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"AjaxPortal is prone to a file inclusion vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

ajaxPort = http_get_port(default:80);

foreach dir (make_list_unique("/", "/ajaxportal", "/portal", http_cgi_dirs(port:ajaxPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:dir + "/install/index.php", port:ajaxPort);

  if(rcvRes =~ "MyioSoft EasyInstaller" &&
     egrep(pattern:"^HTTP/1\.[01] 200", string:rcvRes))
  {
    ajaxVer = get_kb_item("www/" + ajaxPort + "/AjaxPortal");
    ajaxVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ajaxVer);
    if(ajaxVer[1] != NULL)
    {
      if(version_is_equal(version:ajaxVer[1], test_version:"3.0"))
      {
         security_message(port:ajaxPort);
         exit(0);
      }
    }
  }
}

exit(99);
