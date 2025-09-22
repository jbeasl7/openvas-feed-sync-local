# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117618");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-08-12 13:09:57 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-14 18:39:00 +0000 (Tue, 14 Sep 2021)");

  script_cve_id("CVE-2021-35946", "CVE-2021-35947", "CVE-2021-35948", "CVE-2021-35949");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud < 10.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-35946: Federated share recipient can increase permissions

  - CVE-2021-35947: Full path and username disclosure in public links

  - CVE-2021-35948: Session fixation on public links

  - CVE-2021-35949: Shareinfo url doesn't verify file drop permissions");

  script_tag(name:"affected", value:"ownCloud version 10.7 and prior.");

  script_tag(name:"solution", value:"Update to version 10.8 or later.");

  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/cve-2021-35946/");
  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/cve-2021-35947/");
  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/cve-2021-35948/");
  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/cve-2021-35949/");

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

if (version_is_less(version: version, test_version: "10.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
