# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netatalk:netatalk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152540");
  script_version("2024-08-08T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:42 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-07-03 04:43:20 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 19:28:25 +0000 (Wed, 07 Aug 2024)");

  script_cve_id("CVE-2024-38439", "CVE-2024-38440", "CVE-2024-38441");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Netatalk < 3.2.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_netatalk_asip_afp_detect.nasl");
  script_mandatory_keys("netatalk/detected");

  script_tag(name:"summary", value:"Netatalk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-38439: Heap out-of-bounds write in uams_pam.c

  - CVE-2024-38440: Heap out-of-bounds write in uams_dhx_pam.c

  - CVE-2024-38441: Heap out-of-bounds write in directory.c");

  script_tag(name:"affected", value:"Netatalk prior to version 3.2.1.");

  script_tag(name:"solution", value:"Update to version 3.2.1 or later.");

  script_xref(name:"URL", value:"https://github.com/Netatalk/netatalk/security/advisories/GHSA-8r68-857c-4rqc");
  script_xref(name:"URL", value:"https://github.com/Netatalk/netatalk/security/advisories/GHSA-mxx4-9fhm-r3w5");
  script_xref(name:"URL", value:"https://github.com/Netatalk/netatalk/security/advisories/GHSA-mj6v-cr68-mj9q");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
