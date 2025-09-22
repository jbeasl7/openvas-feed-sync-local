# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105594");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-04-04 11:42:25 +0200 (Mon, 04 Apr 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-3626");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiOS Multiple Vulnerabilities (FG-IR-16-003)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("forti/FortiOS/version");

  script_tag(name:"summary", value:"Fortinet FortiOS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - It is possible to inject malicious script through the DHCP HOSTNAME option. The malicious script
  code is injected into the device's `DHCP Monitor` page (System->Monitor->DHCP Monitor) on the
  web-based interface which is accessible by the webui administrators.

  - The FortiOS webui accepts a user-controlled input that specifies a link to an external site, and
  uses that link in a redirect. The redirect input parameter is also prone to a cross site
  scripting.");

  script_tag(name:"affected", value:"Fortinet FortiOS 5.0.0 prior to 5.0.13 and 5.2.0 prior to
  5.2.4.");

  script_tag(name:"solution", value:"Update to version 5.0.13, 5.2.4, 5.4.0 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-003");
  script_xref(name:"URL", value:"http://fortiguard.com/advisory/fortios-open-redirect-vulnerability");
  script_xref(name:"Advisory-ID", value:"FG-IR-16-003");

  exit(0);
}

include("version_func.inc");

if (!version = get_kb_item("forti/FortiOS/version"))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.13");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2.0", test_version_up: "5.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.4 / 5.4.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
