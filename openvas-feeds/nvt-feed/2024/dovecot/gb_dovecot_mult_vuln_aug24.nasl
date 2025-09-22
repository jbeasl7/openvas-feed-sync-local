# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dovecot:dovecot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114754");
  script_version("2024-08-16T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-08-16 05:05:44 +0000 (Fri, 16 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-15 11:17:16 +0000 (Thu, 15 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2024-23184", "CVE-2024-23185");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dovecot 2.2.x < 2.3.21.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  CVE-2024-23184: Having a large number of address headers (From, To, Cc, Bcc, etc.) becomes
  excessively CPU intensive

  CVE-2024-23185: Very large headers can cause resource exhaustion when parsing message");

  script_tag(name:"affected", value:"Dovecot versions 2.2.x and 2.3.x.");

  script_tag(name:"solution", value:"Update to version 2.3.21.1 or later.

  Workaround:

  One can implement restrictions on (address) headers on MTA component preceding Dovecot.");

  script_xref(name:"URL", value:"https://dovecot.org/mailman3/hyperkitty/list/dovecot-news@dovecot.org/thread/2CSVL56LFPAXVLWMGXEIWZL736PSYHP5/");
  script_xref(name:"URL", value:"https://dovecot.org/mailman3/hyperkitty/list/dovecot-news@dovecot.org/thread/VDC6SCNH7YBLECYSIFCIVOUHML7ASGHE/");
  script_xref(name:"URL", value:"https://dovecot.org/mailman3/hyperkitty/list/dovecot-news@dovecot.org/thread/HLWWFDTXRB7HWDBDZN2OAL4P345Y3LXG/");
  script_xref(name:"URL", value:"https://github.com/dovecot/core/commit/586b3603a57e2a40534d4c69e8ac2a045e8e3128");
  script_xref(name:"URL", value:"https://github.com/dovecot/core/commit/f8b5e476dce314ea3f557330eeaa9c5b29159957");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/08/15/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/08/15/4");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2.2", test_version_up: "2.3.21.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.21.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
