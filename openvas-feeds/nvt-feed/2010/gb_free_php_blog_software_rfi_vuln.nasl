# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902056");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-05-28 16:52:49 +0200 (Fri, 28 May 2010)");
  script_cve_id("CVE-2010-1978");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreePHPBlogSoftware 'default_theme.php' RFI Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39321");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39233");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57560");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error an in 'default_theme.php' script, which
  fails to properly sanitize user input supplied to the 'phpincdir' parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"FreePHPBlogSoftware is prone to a remote file inclusion (RFI)
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to include
  arbitrary remote file containing malicious PHP code and execute it in the context of the webserver
  process.");

  script_tag(name:"affected", value:"FreePHPBlogSoftware version 1.0.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/fpws", "/FPWS", "/", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/index.php", port:port);

  if(">FreePHPBlogSoftware<" >< res) {

    req = http_get(item:dir + "/includes/themes_meta.inc", port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    version = eregmatch(pattern:"Version: ([0-9.]+)", string:res);
    if(!isnull(version[1])) {
      if(version_is_equal(version:version[1], test_version:"1.0")) {
        report = report_fixed_ver(installed_version:version[1], fixed_version:"None");
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
