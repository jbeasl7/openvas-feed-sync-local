# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140539");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2017-11-27 09:50:38 +0700 (Mon, 27 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-04 18:15:00 +0000 (Tue, 04 May 2021)");

  script_cve_id("CVE-2017-16943", "CVE-2017-16944");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim Multiple RCE Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("gb_exim_smtp_detect.nasl");
  script_mandatory_keys("exim/detected");

  script_tag(name:"summary", value:"Exim is prone to multiple remote code execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-16943: Use-after-free vulnerability while reading mail header

  - CVE-2017-16944: Exim handles BDAT data incorrectly and leads to crash");

  script_tag(name:"impact", value:"A remote attacker may execute arbitrary commands or conduct a
  denial of service attack.");

  script_tag(name:"affected", value:"Exim version 4.88 and 4.89.");

  script_tag(name:"solution", value:"Apply the provided patch or update to version 4.90 or later. As
  a mitigation set 'chunking_advertise_hosts = ' in the Exim configuration.");

  script_xref(name:"URL", value:"https://lists.exim.org/lurker/message/20171125.034842.d1d75cac.en.html");
  script_xref(name:"URL", value:"https://bugs.exim.org/show_bug.cgi?id=2199");
  script_xref(name:"URL", value:"https://bugs.exim.org/show_bug.cgi?id=2201");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.88", test_version2: "4.89")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
