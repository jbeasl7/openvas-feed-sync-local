# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107444");
  script_version("2023-11-17T16:10:13+0000");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2019-01-09 12:29:11 +0100 (Wed, 09 Jan 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:00:00 +0000 (Tue, 16 Aug 2022)");

  script_cve_id("CVE-2018-0732", "CVE-2018-0734", "CVE-2018-0737", "CVE-2018-5407");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 7.1.4 Multiple Vulnerabilities (TNS-2018-17)");

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tenable Nessus is affected by multiple vulnerabilities:

  - CVE-2018-0732: A flaw in the bundled third-party component OpenSSL library's key handling during
  a TLS handshake that causes a denial of service vulnerability.

  - CVE-2018-0734: A flaw in the bundled third-party component OpenSSL library's DSA signature
  algorithm that renders it vulnerable to a timing side channel attack. An attacker could leverage
  this vulnerability to recover the private key.

  - CVE-2018-0737: A flaw in the bundled third-party component OpenSSL library's RSA Key generation
  algorithm that allows a cache timing side channel attack to recover the private key.

  - CVE-2018-5407: A flaw in the bundled third-party component OpenSSL library's Simultaneous
  Multithreading (SMT) architectures which render it vulnerable to side-channel leakage. This issue
  is known as 'PortSmash'. An attacker could possibly use this issue to perform a timing side-channel
  attack and recover private keys.");

  script_tag(name:"impact", value:"An attacker could leverage this vulnerability to recover the
  private key and could possibly use this issue to perform a timing side-channel attack and recover
  private keys.");

  script_tag(name:"affected", value:"Tenable Nessus versions prior to version 7.1.4.");

  script_tag(name:"solution", value:"Update to version 7.1.4 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2018-17");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.1.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.1.4", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
