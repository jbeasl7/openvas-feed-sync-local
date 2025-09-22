# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117690");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-09-22 08:09:19 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-01 02:59:00 +0000 (Wed, 01 Feb 2017)");

  script_cve_id("CVE-2016-5876");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud Insecure Direct Object Reference Vulnerability (oC-SA-2016-010)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  script_tag(name:"summary", value:"ownCloud is prone to an insecure direct object reference
  vulnerability in the Gallery app.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ownCloud was vulnerable to a insecure direct object reference.
  Any unauthenticated user would be able to download any image from the server if the gallery app is
  enabled.");

  script_tag(name:"affected", value:"ownCloud version prior to 8.2.6 and 9.x before 9.0.3 if the
  gallery app is enabled.");

  script_tag(name:"solution", value:"Update to version 8.2.6, 9.0.3 or later.");

  script_xref(name:"URL", value:"https://github.com/owncloud/security-advisories/blob/master/server/oc-sa-2016-010.json");

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

if (version_is_less(version: version, test_version: "8.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
