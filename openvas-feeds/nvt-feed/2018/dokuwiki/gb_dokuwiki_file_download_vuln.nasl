# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dokuwiki:dokuwiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140814");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-27 10:06:40 +0700 (Tue, 27 Feb 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-07 01:29:00 +0000 (Sat, 07 Jul 2018)");

  script_cve_id("CVE-2017-18123");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DokuWiki Reflected File Download Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_mandatory_keys("dokuwiki/installed");

  script_tag(name:"summary", value:"The call parameter of /lib/exe/ajax.php in DokuWiki does not properly encode
user input, which leads to a reflected file download vulnerability, and allows remote attackers to run arbitrary
programs.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"DokuWiki 2017-02-19e and prior.");

  script_tag(name:"solution", value:"Apply the provided patch.");

  script_xref(name:"URL", value:"https://github.com/splitbrain/dokuwiki/issues/2029");

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

url = dir + '/lib/exe/ajax.php?call=%7c%7c%63%61%6c%63%7c%7c';

if (http_vuln_check(port: port, url: url, pattern: "AJAX call '\|\|calc\|\|' unknown!", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
