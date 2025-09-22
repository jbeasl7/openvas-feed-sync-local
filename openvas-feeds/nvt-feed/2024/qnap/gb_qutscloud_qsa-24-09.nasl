# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qutscloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126630");
  script_version("2024-03-15T05:06:15+0000");
  script_tag(name:"last_modification", value:"2024-03-15 05:06:15 +0000 (Fri, 15 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-12 11:31:42 +0000 (Tue, 12 Mar 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-13 14:25:02 +0000 (Wed, 13 Mar 2024)");

  script_cve_id("CVE-2024-21899", "CVE-2024-21900", "CVE-2024-21901");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTScloud Multiple Vulnerabilities (QSA-24-09)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qutscloud/detected");

  script_tag(name:"summary", value:"QNAP QuTScloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-21899: Improper authentication which could allow users to compromise the security of
  the system via a network

  - CVE-2024-21900: Injection vulnerability which could allow an authenticated users to execute
  commands via a network

  - CVE-2024-21901: SQL injection (SQLi) which could allow an authenticated administrators to
  inject malicious code via a network");

  script_tag(name:"affected", value:"QNAP QuTScloud c5.x.");

  script_tag(name:"solution", value:"Update to version c5.1.5.2651 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-09");

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
