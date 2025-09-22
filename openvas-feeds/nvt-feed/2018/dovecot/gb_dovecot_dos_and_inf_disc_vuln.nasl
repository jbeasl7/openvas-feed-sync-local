# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113214");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-06-26 12:44:04 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-04 01:29:00 +0000 (Wed, 04 Apr 2018)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-14461");

  script_name("Dovecot <= 2.2.33 DoS and Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to a vulnerability that may lead to Denial of Service and Information Disclosure.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A specially crafted email delivered over SMTP and passed on to Dovecot can trigger an out of bounds read
  resulting in potential sensitive information disclosure and denial of service.

  In order to trigger this vulnerability, an attacker needs to send a specially crafted amail message to the server.");

  script_tag(name:"affected", value:"Dovecot version 2.0.0 through 2.2.33.");

  script_tag(name:"solution", value:"Update to version 2.2.34.");

  script_xref(name:"URL", value:"https://www.dovecot.org/list/dovecot-news/2018-February/000370.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103201");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q1/205");

  exit(0);
}

CPE = "cpe:/a:dovecot:dovecot";

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "2.2.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
