# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:unified_computing_system";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103805");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-10-10 19:10:32 +0200 (Thu, 10 Oct 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2013-1182", "CVE-2013-1183", "CVE-2013-1184", "CVE-2013-1185",
                "CVE-2013-1186");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Computing System Multiple Vulnerabilities (cisco-sa-20130424-ucsmulti)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ucs_manager_http_detect.nasl");
  script_mandatory_keys("cisco/ucs_manager/detected");

  script_tag(name:"summary", value:"Cisco Unified Computing System is prone to multiple
  vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exit:

  - CVE-2013-1182: LDAP user authentication bypass

  - CVE-2013-1183: IPMI buffer overflow

  - CVE-2013-1184: Management API denial of service (DoS)

  - CVE-2013-1185: Information disclosure

  - CVE-2013-1186: KVM authentication bypass");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130424-ucsmulti");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

vers = eregmatch(pattern: "^([0-9.]+)\(([^)]+)\)", string: version);
if (isnull(vers[1]) || isnull(vers[2]))
  exit(0);

major = vers[1];
build = vers[2];

vuln = FALSE;

# cisco recommended to update to 2.1.1e. So we check for < 2.1.1e. Example
# Version: 2.0(1s)
if (version_is_less(version: major, test_version: "2.1"))
  vuln = TRUE;
else if (version_is_equal(version: major, test_version: "2.1")) {
  if (build =~ "^(0[^0-9]|1[a-d])")
    vuln = TRUE;
}

if (vuln) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.1e");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
