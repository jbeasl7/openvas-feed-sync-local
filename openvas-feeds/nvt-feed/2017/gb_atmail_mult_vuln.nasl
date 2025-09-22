# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atmail:atmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106861");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-09 16:32:29 +0700 (Fri, 09 Jun 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-13 13:34:00 +0000 (Tue, 13 Jun 2017)");

  script_cve_id("CVE-2017-9517", "CVE-2017-9518", "CVE-2017-9519", "CVE-2017-11617");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("atmail Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("atmail_detect.nasl");
  script_mandatory_keys("Atmail/installed");

  script_tag(name:"summary", value:"atmail is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"atmail is prone to multiple vulnerabilities:

  - CSRF which allows an attacker to upload and import users via CSV

  - CSRF which allows an attacker can change SMTP hostname and hijack all emails

  - CSRF which allows an attacker create a user

  - XSS: send email with payload

  - It's been noted that login to user account via admin is being logged as USER LOGIN. The logs does not show that
login activity has been made by admin.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"atmail before 7.8.0.2.");

  script_tag(name:"solution", value:"Update to version 7.8.0.2 or later.");

  script_xref(name:"URL", value:"https://help.atmail.com/hc/en-us/articles/115007169147-Minor-Update-7-8-0-2-ActiveSync-2-3-6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "7.8.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.0.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
