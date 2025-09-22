# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:buffalo:ls210d_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103129");
  script_version("2025-05-20T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-20 05:40:25 +0000 (Tue, 20 May 2025)");
  script_tag(name:"creation_date", value:"2024-05-17 15:01:24 +0000 (Fri, 17 May 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-18 15:05:25 +0000 (Thu, 18 Jan 2024)");

  script_cve_id("CVE-2023-51073", "CVE-2004-2320");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Buffalo LS210D < 1.82 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_buffalo_airstation_detect.nasl");
  script_mandatory_keys("buffalo/airstation/detected");

  script_tag(name:"summary", value:"Buffalo LS210D is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target
  host.");

  script_tag(name:"insight", value: "The following flaws exist:

  - CVE-2023-51073: Arbitrary code execution via the Firmware Update Script
  at /etc/init.d/update_notifications.sh

  - CVE-2004-2320: The default configuration of BEA WebLogic Server and Express responds to the HTTP
  TRACE request, which can allow remote attackers to steal information using cross-site tracing
  (XST) attacks in applications that are vulnerable to cross-site scripting.

  - No CVE: Multiple unspecified vulnerabilities in the Settings component");

  script_tag(name:"affected", value:"Buffalo LS210D firmware prior to version 1.82.");

  script_tag(name:"solution", value:"Update to firmware version 1.82 or later.");

  script_xref(name:"URL", value:"https://github.com/christopher-pace/CVE-2023-51073");
  script_xref(name:"URL", value:"https://dd00b71c8b1dfd11ad96-382cb7eb4238b9ee1c11c6780d1d2d1e.ssl.cf1.rackcdn.com/ls200-v184_win_en.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.82")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.82");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
