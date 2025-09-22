# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fortinet:fortimail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805646");
  script_version("2024-12-24T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-12-24 05:05:31 +0000 (Tue, 24 Dec 2024)");
  script_tag(name:"creation_date", value:"2015-06-08 11:54:11 +0530 (Mon, 08 Jun 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-8617");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiMail Stored XSS Vulnerability (FG-IR-15-005)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortimail_consolidation.nasl");
  script_mandatory_keys("fortinet/fortimail/detected");

  script_tag(name:"summary", value:"Fortinet FortiMail is prone to a stored cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the Web Action Quarantine Release
  feature does not validate input before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to create
  a specially crafted request that would execute arbitrary script code in a user's browser session
  within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Fortinet FortiMail versions prior to 4.3.9, 5.0.0 prior to
  5.0.8, 5.1.0 prior to 5.1.5 and 5.2.0 prior to 5.2.3.");

  script_tag(name:"solution", value:"Update to Fortinet FortiMail 4.3.9, 5.0.8, 5.1.5, 5.2.3 or
  later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-15-005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72820");
  script_xref(name:"Advisory-ID", value:"FG-IR-15-005");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "4.3.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.9");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.1.0", test_version2: "5.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.5");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
