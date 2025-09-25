# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155383");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-23 07:56:40 +0000 (Tue, 23 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_cve_id("CVE-2023-48795");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ProFTPD < 1.3.8b OpenSSH Terrapin Attack");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_proftpd_consolidation.nasl");
  script_mandatory_keys("proftpd/detected");

  script_tag(name:"summary", value:"ProFTPD is prone to the SSH 'Terrapin' vulnerability when using
  the chacha20-poly1305@openssh.com cipher.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSH is vulnerable to a machine-in-the-middle attack, caused
  by a flaw in the extension negotiation process in the SSH transport protocol when used with
  certain OpenSSH extensions.");

  script_tag(name:"impact", value:"A remote attacker could exploit this vulnerability to launch a
  machine-in-the-middle attack and strip an arbitrary number of messages after the initial key
  exchange, breaking SSH extension negotiation and downgrading the client connection security.");

  script_tag(name:"affected", value:"ProFTPD prior to version 1.3.8b.");

  script_tag(name:"solution", value:"Update to version 1.3.8b or later.");

  script_xref(name:"URL", value:"https://github.com/proftpd/proftpd/issues/1760");
  script_xref(name:"URL", value:"https://terrapin-attack.com");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20231024.txt");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (revcomp(a: version, b: "1.3.8b") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.8b");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
