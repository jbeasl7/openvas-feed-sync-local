# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:chef:chef_manage";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106678");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-03-21 14:09:13 +0700 (Tue, 21 Mar 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-7174");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Chef Manage RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chef_manage_detect.nasl");
  script_mandatory_keys("chef_manage/installed");

  script_tag(name:"summary", value:"Chef Manage is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The user-account creation feature allows remote attackers to execute
arbitrary code.");

  script_tag(name:"affected", value:"Chef Manage 2.1.0 until 2.4.4");

  script_tag(name:"solution", value:"Update to version 2.4.5 or later.");

  script_xref(name:"URL", value:"https://discourse.chef.io/t/chef-manage-2-4-5-security-release/10599");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "2.1.0", test_version2: "2.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
