# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:fortinet:fortios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805639");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2015-06-16 12:01:44 +0530 (Tue, 16 Jun 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-8616", "CVE-2015-1880");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiGate Reflected XSS Vulnerability (FG-IR-15-005)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortigate_consolidation.nasl");
  script_mandatory_keys("fortinet/fortigate/detected");

  script_tag(name:"summary", value:"Fortinet FortiGate is prone to a reflected cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the sslvpn login page does not validate
  input before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow a context-dependent attacker
  to create a specially crafted request that would execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Fortinet FortiGate version 5.2.0 through 5.2.2.");

  script_tag(name:"solution", value:"Update to version 5.2.3 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-15-005");
  script_xref(name:"Advisory-ID", value:"FG-IR-15-005");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
