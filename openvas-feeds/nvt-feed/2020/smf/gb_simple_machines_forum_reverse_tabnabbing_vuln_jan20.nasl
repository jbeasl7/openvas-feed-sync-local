# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:simplemachines:smf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113631");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2020-01-24 09:53:42 +0000 (Fri, 24 Jan 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-12490");

  script_name("Simple Machines Forum (SMF) < 2.0.16 Reverse Tabnabbing Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_http_detect.nasl");
  script_mandatory_keys("smf/detected");

  script_tag(name:"summary", value:"Simple Machine Forum (SMF) is prone to a reverse tabnabbing
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability can occur because of the use of _blank for
  external links.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to modify the
  target page or lure users of the site to a phishing page.");

  script_tag(name:"affected", value:"SMF versions through 2.0.15.");

  script_tag(name:"solution", value:"Update to version 2.0.16 or later.");

  script_xref(name:"URL", value:"https://www.simplemachines.org/community/index.php?topic=570986.0");

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

if (version_is_less(version: version, test_version: "2.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
