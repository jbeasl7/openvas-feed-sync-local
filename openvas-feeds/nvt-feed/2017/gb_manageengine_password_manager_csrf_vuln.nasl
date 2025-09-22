# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:manageengine:password_manager_pro";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106790");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-04-26 12:24:01 +0200 (Wed, 26 Apr 2017)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-26 16:44:00 +0000 (Wed, 26 Apr 2017)");

  script_cve_id("CVE-2016-1161");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ManageEngine Password Manager Pro CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_pass_mang_pro_detect.nasl");
  script_mandatory_keys("ManageEngine/Password_Manager/installed");

  script_tag(name:"summary", value:"ManageEngine Password Manager Pro is prone to a CSRF vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The personal area of the product, in which a user store his personal
password entries for different account type, is exposed to CSRF attacks. Using this attack, it's possible to
create or delete an arbitrary account.");

  script_tag(name:"affected", value:"ManageEngine Password Manager Pro prior to build 8500.");

  script_tag(name:"solution", value:"Update to build 8500 or later.");

  script_xref(name:"URL", value:"https://www.excellium-services.com/cert-xlm-advisory/cve-2016-1161/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "8500")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8500");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
