# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807444");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-1501");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-12 02:48:00 +0000 (Tue, 12 Jan 2016)");
  script_tag(name:"creation_date", value:"2016-03-02 15:04:46 +0530 (Wed, 02 Mar 2016)");
  script_name("ownCloud 8.0.x < 8.0.9, 8.1.x < 8.1.4 Path Disclosure Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2016-004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/80382");

  script_tag(name:"summary", value:"ownCloud is prone to path disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to returned exception error messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow an authenticated adversary to
  gain information about the installation path of the ownCloud instance.");

  script_tag(name:"affected", value:"ownCloud Server versions 8.x prior to 8.0.9 and 8.1.x prior to
  8.1.4.");

  script_tag(name:"solution", value:"Update to version 8.0.9, 8.1.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

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

if (version !~ "^8\.")
  exit(99);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.8"))
  fix = "8.0.9";

else if (version_in_range(version: version, test_version: "8.1.0", test_version2: "8.1.3"))
  fix = "8.1.4";

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
