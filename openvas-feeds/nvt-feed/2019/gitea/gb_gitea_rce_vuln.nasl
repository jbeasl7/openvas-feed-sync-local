# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitea:gitea";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142305");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-04-25 08:34:13 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-04 13:52:00 +0000 (Thu, 04 Feb 2021)");

  script_cve_id("CVE-2019-11228", "CVE-2019-11229");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gitea < 1.7.6 or < 1.8.0-rc3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitea_http_detect.nasl");
  script_mandatory_keys("gitea/detected");

  script_tag(name:"summary", value:"Gitea is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Gitea is prone to multiple vulnerabilities:

  - repo/setting.go does not validate the form.MirrorAddress before calling SaveAddress (CVE-2019-11228)

  - models/repo_mirror.go mishandles mirror repo URL settings, leading to remote code execution (CVE-2019-11229)");

  script_tag(name:"affected", value:"Gitea versions prior to 1.7.6 and 1.8.x before 1.8-rc3.");

  script_tag(name:"solution", value:"Update to version 1.7.6, 1.8-rc3 or later.");

  script_xref(name:"URL", value:"https://github.com/go-gitea/gitea/releases/tag/v1.7.6");
  script_xref(name:"URL", value:"https://github.com/go-gitea/gitea/releases/tag/v1.8.0-rc3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "1.7.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.6", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.8.0.rc1", test_version2: "1.8.0.rc2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.0.rc3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
