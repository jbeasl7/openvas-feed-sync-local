# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fortinet:fortiauthenticator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105228");
  script_version("2024-11-12T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-11-12 05:05:34 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"creation_date", value:"2015-03-02 10:40:16 +0100 (Mon, 02 Mar 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-1455", "CVE-2015-1456", "CVE-2015-1457", "CVE-2015-1458",
                "CVE-2015-1459");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiAuthenticator Appliance Multiple Security Vulnerabilities (FG-IR-15-003)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_forti_authenticator_version.nasl");
  script_mandatory_keys("fortiauthenticator/version");

  script_tag(name:"summary", value:"Fortinet FortiAuthenticator is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2015-1455: Hardcoded PostgreSQL user and password

  - CVE-2015-1456: PostgreSQL users and passwords are logged in cleartext at startup

  - CVE-2015-1457: Local file system disclosure

  - CVE-2015-1459: XSS vulnerability");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary
  script code in the context of the vulnerable site, potentially allowing the attacker to steal
  cookie-based authentication credentials, execute arbitrary commands and gain access to potentially
  sensitive information.");

  script_tag(name:"affected", value:"Fortinet FortiAuthenticator prior to version 3.2.1");

  script_tag(name:"solution", value:"Update to version 3.2.1 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72378");
  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-15-003");
  script_xref(name:"Advisory-ID", value:"FG-IR-15-003");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "3.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
