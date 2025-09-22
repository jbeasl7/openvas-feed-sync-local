# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144911");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2020-12-17 06:34:07 +0000 (Thu, 17 Dec 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-14 19:18:00 +0000 (Mon, 14 Dec 2020)");

  script_cve_id("CVE-2020-29254");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tiki Wiki CMS Groupware < 22 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_mandatory_keys("tiki/wiki/detected");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Local (php) File Inclusion: In TikiWiki, an user can be given the permission to edit .tpl
  templates. This feature can be abused to escalate the users privileges by inserting the following
  pieceof smarty code: {include file='../db/local.php'}. The code snippet includes Tiki Wikis
  database configuration file and displays it in the pages source code. Any other www-data readable
  file like '/etc/passwd' can be included as well.

  - Cross-Site Request Forgery (CSRF): Tiki Wiki allows templates to be edited without CSRF
  protection. This could allow an unauthenticated, remote attacker to conduct a cross-site request
  forgery (CSRF) attack and perform arbitrary actions on an affected system. The vulnerability is
  due to insufficient CSRF protections for the web-based management interface of the affected
  system. An attacker could exploit this vulnerability by persuading a user of the interface to
  follow a maliciously crafted link. (CVE-2020-29254)

  - Information Exposure: An user who is able to edit template files can use smarty code to include
  Files like the database configuration file which allows access to TikiWikis Database.");

  script_tag(name:"impact", value:"- Local (php) File Inclusion: The config file displays
  TikiWikis database credentials in cleartext.

  - Cross-Site Request Forgery (CSRF): A successful exploit could allow the attacker to perform
  arbitrary actions on an affected system with the privileges of the user. These action include
  allowing attackers to submit their own code through an authenticated user resulting in local file
  Inclusion. If an authenticated user who is able to edit Tiki Wiki templates visits an malicious
  website, template code can be edited.

  - Information Exposure: The User can authenticate against it and simply give itself admin
  privileges or compromise the administrator account.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware through version 21.2 and probably
  prior.");

  script_tag(name:"solution", value:"Update to version 22 which disables and hides the risky
  preferences by default.");

  script_xref(name:"URL", value:"https://doc.tiki.org/CVE-2020-29254");
  script_xref(name:"URL", value:"https://github.com/S1lkys/CVE-2020-29254");
  script_xref(name:"URL", value:"https://github.com/S1lkys/CVE-2020-29254/blob/main/Tiki-Wiki%2021.2%20by%20Maximilian%20Barz.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
