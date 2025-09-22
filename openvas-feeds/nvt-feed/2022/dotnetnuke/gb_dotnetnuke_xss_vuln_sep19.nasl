# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dnnsoftware:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126106");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2022-08-08 12:04:16 +0000 (Mon, 08 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-01 23:15:00 +0000 (Tue, 01 Oct 2019)");

  script_cve_id("CVE-2019-12562");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DNN (DotNetNuke) <= 9.3.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_consolidation.nasl");
  script_mandatory_keys("dotnetnuke/detected");

  script_tag(name:"summary", value:"DNN (formerly DotNetNuke) is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This might lead attacker to perform any action with admin
  privileges such as managing content, adding users, uploading backdoors to the server, etc.");

  script_tag(name:"affected", value:"DNN version 9.3.2 and prior.");

  script_tag(name:"solution", value:"Update to version 9.4.0 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/cve/CVE-2019-12562");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-5whq-j5qg-wjvp");
  script_xref(name:"URL", value:"https://mayaseven.com/cve-2019-12562-stored-cross-site-scripting-in-dotnetnuke-dnn-version-v9-3-2/");
  script_xref(name:"URL", value:"https://dnncommunity.org/security");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "9.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
