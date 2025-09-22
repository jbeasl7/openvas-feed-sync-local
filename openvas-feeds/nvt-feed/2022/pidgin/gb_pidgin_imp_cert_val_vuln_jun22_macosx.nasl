# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pidgin:pidgin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127091");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-07-15 10:30:46 +0000 (Fri, 15 Jul 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-09 19:01:00 +0000 (Thu, 09 Jun 2022)");

  script_cve_id("CVE-2022-26491");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pidgin < 2.14.9 Improper Certificate Validation Vulnerability - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_pidgin_detect_macosx.nasl");
  script_mandatory_keys("Pidgin/MacOSX/Version");

  script_tag(name:"summary", value:"Pidgin is prone to an improper certificate validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A remote attacker can obtain users credentials and all
  communication content by redirecting a client connection to malicious server.");

  script_tag(name:"affected", value:"Pidgin prior to version 2.14.9.");

  script_tag(name:"solution", value:"Update to version 2.14.9 or later.");

  script_xref(name:"URL", value:"https://pidgin.im/about/security/advisories/cve-2022-26491/");
  script_xref(name:"URL", value:"https://keep.imfreedom.org/pidgin/pidgin/file/release-2.x.y/ChangeLog");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.14.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.14.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
