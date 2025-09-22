# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154149");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-10 02:52:57 +0000 (Mon, 10 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-13086");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Information Disclosure Vulnerability (QSA-25-03)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An exposure of sensitive information vulnerability has been
  reported to affect certain legacy versions of QuTS hero.");

  script_tag(name:"impact", value:"If exploited, the vulnerability could allow remote attackers to
  compromise the security of the system.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h5.x prior to h5.2.0.2851 build
  20240808.");

  script_tag(name:"solution", value:"Update to version h5.2.0.2851 build 20240808 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-25-03");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h5\.") {
  if (version_is_less(version: version, test_version: "h5.2.0.2851")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.2.0.2851", fixed_build: "20240808");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.2.0.2851") &&
     (!build || version_is_less(version: build, test_version: "20240808"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.2.0.2851", fixed_build: "20240808");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
