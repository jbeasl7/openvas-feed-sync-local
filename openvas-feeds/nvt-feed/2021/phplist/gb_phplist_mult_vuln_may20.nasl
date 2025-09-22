# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phplist:phplist";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146210");
  script_version("2025-05-20T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-20 05:40:25 +0000 (Tue, 20 May 2025)");
  script_tag(name:"creation_date", value:"2021-07-02 06:27:13 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-01 21:18:00 +0000 (Mon, 01 Feb 2021)");

  script_cve_id("CVE-2020-23190", "CVE-2020-23207", "CVE-2020-23208", "CVE-2020-23209",
                "CVE-2020-23214", "CVE-2020-23217", "CVE-2020-23361");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpList < 3.5.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phplist_http_detect.nasl");
  script_mandatory_keys("phplist/detected");

  script_tag(name:"summary", value:"phpList is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-23207: Stored XSS allows attackers to execute arbitrary web scripts or HTML via a
  crafted payload entered into the 'Edit Values' field under the 'Configure Attributes' module

  - CVE-2020-23208: Stored XSS allows attackers to execute arbitrary web scripts or HTML via a
  crafted payload entered into the 'Send test' field under the 'Start or continue campaign' module

  - CVE-2020-23209: Stored XSS allows attackers to execute arbitrary web scripts or HTML via a
  crafted payload entered into the 'List Description' field under the 'Edit A List' module

  - CVE-2020-23214: Stored XSS allows attackers to execute arbitrary web scripts or HTML via a
  crafted payload entered into the 'Configure categories' field under the 'Categorise Lists' module

  - CVE-2020-23190, CVE-2020-23217: Stored XSS allows attackers to execute arbitrary web scripts or
  HTML via a crafted payload entered into the 'Add a list' field under the 'Import Emails' module

  - CVE-2020-23361: Allows type juggling for login bypass because == is used instead of === for
  password hashes, which mishandles hashes that begin with 0e followed by exclusively numerical
  characters");

  script_tag(name:"affected", value:"phpList version 3.5.3 and prior.");

  script_tag(name:"solution", value:"Update to version 3.5.4 or later.");

  script_xref(name:"URL", value:"https://www.phplist.org/newslist/phplist-3-5-4-release-notes/");
  script_xref(name:"URL", value:"https://github.com/phpList/phplist3/issues/664");
  script_xref(name:"URL", value:"https://github.com/phpList/phplist3/issues/665");
  script_xref(name:"URL", value:"https://github.com/phpList/phplist3/issues/666");
  script_xref(name:"URL", value:"https://github.com/phpList/phplist3/issues/667");
  script_xref(name:"URL", value:"https://github.com/phpList/phplist3/issues/669");
  script_xref(name:"URL", value:"https://github.com/phpList/phplist3/issues/672");
  script_xref(name:"URL", value:"https://github.com/phpList/phplist3/issues/668");

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

if (version_is_less(version: version, test_version: "3.5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
