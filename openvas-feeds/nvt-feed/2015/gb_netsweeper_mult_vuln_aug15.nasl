# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netsweeper:netsweeper";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805962");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2014-9612", "CVE-2014-9605", "CVE-2014-9610", "CVE-2014-9619");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-20 16:17:00 +0000 (Thu, 20 Feb 2020)");
  script_tag(name:"creation_date", value:"2015-08-25 14:52:59 +0530 (Tue, 25 Aug 2015)");

  script_tag(name:"qod_type", value:"exploit");

  script_name("Netsweeper Multiple Vulnerabilities (Aug 2015)");

  script_tag(name:"summary", value:"Netsweeper is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Input passed via 'server' parameter to load_logfiles.php script is not validated before returning to users.

  - The application does not validate input against crafted requests.

  - Unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database
  allowing for the manipulation or disclosure of arbitrary data, allowing
  arbitrary file upload and execution, and authentication bypass.");

  script_tag(name:"affected", value:"Netsweeper before versions 3.1.10, 4.0.9 and 4.1.2.");

  script_tag(name:"solution", value:"Upgrade to Netsweeper version 3.1.10, 4.0.9 or 4.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37927");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37928");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37929");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37932");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_netsweeper_http_detect.nasl");
  script_mandatory_keys("netsweeper/detected");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + '/remotereporter/load_logfiles.php?server="SQL-INJECTION-TEST&url=test';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"SQL-INJECTION-TEST",
                   extra_check: "You have an error in your SQL syntax")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
