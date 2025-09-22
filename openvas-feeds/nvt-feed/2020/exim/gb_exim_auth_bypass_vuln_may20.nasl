# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143882");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2020-05-12 04:48:22 +0000 (Tue, 12 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-04 18:15:00 +0000 (Tue, 04 May 2021)");

  script_cve_id("CVE-2020-12783");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim <= 4.93 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_exim_smtp_detect.nasl");
  script_mandatory_keys("exim/detected");

  script_tag(name:"summary", value:"Exim is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Exim has an out-of-bounds read in the SPA authenticator that
  could result in SPA/NTLM authentication bypass in auths/spa.c and auths/auth-spa.c.");

  script_tag(name:"impact", value:"An attacker can supply customized 'length' and 'offset' to read
  arbitrary memory address.");

  script_tag(name:"affected", value:"Exim version 4.93 and prior.");

  script_tag(name:"solution", value:"Update to version 4.94 or later.");

  script_xref(name:"URL", value:"https://bugs.exim.org/show_bug.cgi?id=2571");
  script_xref(name:"URL", value:"https://git.exim.org/exim.git/commit/57aa14b216432be381b6295c312065b2fd034f86");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.93")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.94");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
