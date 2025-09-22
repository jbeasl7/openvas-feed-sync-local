# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146494");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-08-11 05:47:25 +0000 (Wed, 11 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-01 18:34:00 +0000 (Thu, 01 Jul 2021)");

  script_cve_id("CVE-2021-32925", "CVE-2021-34187", "CVE-2021-37389", "CVE-2021-37390",
                "CVE-2021-37391", "CVE-2021-43687", "CVE-2021-35413", "CVE-2021-35414");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Chamilo LMS < 1.11.16 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-32925: XML External Entity (XXE)

  - CVE-2021-34187: SQL injection (SQLi)

  - CVE-2021-37389, CVE-2021-37390, CVE-2021-37391, CVE-2021-43687: Multiple cross-site scripting
  (XSS)

  - CVE-2021-35413: Authenticated remote code execution (RCE)

  - CVE-2021-35414: SQL injection");

  script_tag(name:"affected", value:"Chamilo LMS version 1.11.14 and prior.");

  script_tag(name:"solution", value:"Update to version 1.11.16 or later.");

  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/e71437c8de809044ba3ae1b181d70857c050a3e9");
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/005dc8e9eccc6ea35264064ae09e2e84af8d5b59");
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/f7f93579ed64765c2667910b9c24d031b0a00571");
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/dfae49f5dc392c00cd43badcb3043db3a646ff0c");
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/3fcc751d5cc7da311532a8756fba5a8778f50ca0");
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/de43a77049771cce08ea7234c5c1510b5af65bc8");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-66-2021-05-21-High-impact-very-low-risk-Authenticated-RCE-in-accessory-script");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-65-2021-05-15-High-impact-very-high-risk-Unauthenticated-SQL-injection-in-plugin");

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

if (version_is_less(version: version, test_version: "1.11.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
