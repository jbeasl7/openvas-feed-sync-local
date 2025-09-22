# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phplist:phplist";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113719");
  script_version("2025-05-20T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-20 05:40:25 +0000 (Tue, 20 May 2025)");
  script_tag(name:"creation_date", value:"2020-07-13 07:24:03 +0000 (Mon, 13 Jul 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-10 18:39:00 +0000 (Fri, 10 Jul 2020)");

  script_cve_id("CVE-2020-15072", "CVE-2020-15073", "CVE-2020-23192", "CVE-2020-23194",
                "CVE-2020-36398", "CVE-2020-36399");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpList < 3.5.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phplist_http_detect.nasl");
  script_mandatory_keys("phplist/detected");

  script_tag(name:"summary", value:"phpList is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-15072: Error-based SQL Injection vulnerability via the Import Administrators section

  - CVE-2020-15073: An XSS vulnerability occurs within the Import Administrators section via upload
  of an edited text document. This also affects the Subscriber Lists section.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker
  to inject arbitrary HTML and JavaScript into the site, read or modify sensitive information or
  execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"phpList through version 3.5.4.");

  script_tag(name:"solution", value:"Update to version 3.5.5.");

  script_xref(name:"URL", value:"https://www.phplist.org/newslist/phplist-3-5-5-release-notes/");

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

if (version_is_less(version: version, test_version: "3.5.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
