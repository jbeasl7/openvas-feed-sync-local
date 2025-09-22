# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141621");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-10-30 14:57:10 +0700 (Tue, 30 Oct 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-26 18:52:00 +0000 (Wed, 26 Apr 2023)");

  script_cve_id("CVE-2018-3953", "CVE-2018-3954", "CVE-2018-3955");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Linksys ESeries Multiple OS Command Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_linksys_devices_consolidation.nasl");
  script_mandatory_keys("linksys/detected");

  script_tag(name:"summary", value:"Linksys ESeries are prone to multiple authenticated OS command execution
vulnerabilities.");

  script_tag(name:"insight", value:"Specially crafted entries to network configuration information can cause
execution of arbitrary system commands, resulting in full control of the device. An attacker can send an
authenticated HTTP request to trigger this vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Linksys E1200 and E2500.");

  script_tag(name:"solution", value:"Update to firmware version 2.0.10 (E1200), 3.0.05 (E2500) or later.");

  script_xref(name:"URL", value:"https://blog.talosintelligence.com/2018/10/vulnerability-spotlight-linksys-eseries.html");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2018-0625");
  script_xref(name:"URL", value:"https://www.linksys.com/us/support-product?pid=01t80000003KRTzAAO");
  script_xref(name:"URL", value:"https://www.linksys.com/us/support-product?pid=01t80000003KZuNAAW");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:linksys:e1200_firmware",
                     "cpe:/o:linksys:e2500_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = infos["version"];

if (cpe == "cpe:/o:linksys:e1200_firmware") {
  if (version_is_less(version: version, test_version: "2.0.10")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.0.10 build 1");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:linksys:e2500_firmware") {
  if (version_is_less(version: version, test_version: "3.0.05")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "3.0.05 build 2");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
