# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qutscloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126595");
  script_version("2024-02-15T14:37:33+0000");
  script_tag(name:"last_modification", value:"2024-02-15 14:37:33 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-13 11:31:42 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2023-47218", "CVE-2023-50358");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTScloud Multiple OS Command Injection Vulnerabilities (QSA-23-57) - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qutscloud/detected");

  script_tag(name:"summary", value:"QNAP QuTScloud is prone to multiple OS command injection
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-47218, CVE-2023-50358: QNAP allows to an OS command injection. If exploited, it could
  allow users to execute commands via network.");

  script_tag(name:"affected", value:"QNAP QuTScloud version c5.x.");

  script_tag(name:"solution", value:"Update to version c5.1.5.2651 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-57");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "c5.0.0", test_version_up: "c5.1.5.2651")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "c5.1.5.2651");
  security_message(port:0, data: report);
  exit(0);
}

exit(99);
