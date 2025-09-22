# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:alinto:sogo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127286");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-12-21 08:40:39 +0000 (Wed, 21 Dec 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-22 13:37:00 +0000 (Thu, 22 Dec 2022)");

  script_cve_id("CVE-2022-4556", "CVE-2022-4558");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SOGo < 5.8.0 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sogo_http_detect.nasl");
  script_mandatory_keys("sogo/detected");

  script_tag(name:"summary", value:"Alinto SOGo (formerly Inverse inc.) is prone to multiple
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-4556: Cross-site scripting (XSS) affects _migrateMailIdentities function in the
  'SoObjects/SOGo/SOGoUserDefaults.m' file of the Identity Handler component.

  - CVE-2022-4558: Cross-site scripting (XSS) affects an unknown part of the file
  'SoObjects/SOGo/NSString+Utilities.m' of the Folder/Mail Handler component.");

  script_tag(name:"affected", value:"Alinto SOGo prior to version 5.8.0.");

  script_tag(name:"solution", value:"Update to version 5.8.0 or later.");

  script_xref(name:"URL", value:"https://github.com/Alinto/sogo/releases/tag/SOGo-5.8.0");
  script_xref(name:"URL", value:"https://github.com/Alinto/sogo/commit/efac49ae91a4a325df9931e78e543f707a0f8e5e");
  script_xref(name:"URL", value:"https://github.com/Alinto/sogo/commit/1e0f5f00890f751e84d67be4f139dd7f00faa5f3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.8.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
