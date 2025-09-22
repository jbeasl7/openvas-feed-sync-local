# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qutscloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126712");
  script_version("2024-08-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-08-13 05:05:46 +0000 (Tue, 13 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-04-29 08:50:42 +0000 (Mon, 29 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:C");

  script_cve_id("CVE-2023-51364", "CVE-2023-51365", "CVE-2024-21905", "CVE-2024-32765");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTScloud Multiple Vulnerabilities (QSA-24-14, QSA-24-16)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qutscloud/detected");

  script_tag(name:"summary", value:"QNAP QuTScloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-51364, CVE-2023-51365: Path traversal vulnerabilities which could allow remote
  attackers to read sensitive data

  - CVE-2024-21905: An integer overflow or wraparound vulnerability which could allow remote
  attackers to compromise the security of the system

  - CVE-2024-32765: An unknown vulnerability which could allow attackers to gain access to the
  system and execute certain functions");

  script_tag(name:"affected", value:"QNAP QuTScloud c5.x prior to c5.1.5.2651.");

  script_tag(name:"solution", value:"Update to version c5.1.5.2651 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-14");
  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-16");

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
