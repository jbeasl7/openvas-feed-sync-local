# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:juniper:junos_space";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105408");
  script_version("2025-01-16T05:37:14+0000");
  script_tag(name:"last_modification", value:"2025-01-16 05:37:14 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-10-16 20:11:07 +0200 (Fri, 16 Oct 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2015-7753", "CVE-2014-0429", "CVE-2014-0456", "CVE-2014-0460",
                "CVE-2014-0453", "CVE-2015-0975", "CVE-2015-3209", "CVE-2014-1568",
                "CVE-2013-2249", "CVE-2013-6438", "CVE-2014-0098", "CVE-2014-6491",
                "CVE-2014-6500", "CVE-2015-0501", "CVE-2014-6478", "CVE-2014-6494",
                "CVE-2014-6495", "CVE-2014-6496", "CVE-2014-6559", "CVE-2015-2620",
                "CVE-2013-5908");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper Networks Junos Space Multiple Vulnerabilities (JSA10698)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_space_consolidation.nasl");
  script_mandatory_keys("juniper/junos/space/detected");

  script_tag(name:"summary", value:"Juniper Networks Junos Space is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities include cross site scripting (XSS), SQL
  injection (SQLi) and command injection vulnerabilities.");

  script_tag(name:"impact", value:"These vulnerabilities may potentially allow a remote
  unauthenticated network based attacker with access to Junos Space to execute arbitrary code on
  Junos Space.");

  script_tag(name:"affected", value:"Juniper Networks Junos Space versions prior to 15.1R1.");

  script_tag(name:"solution", value:"Update to version 15.1R1 or later.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10698");

  exit(0);
}

include("host_details.inc");
include("junos.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(version);

if (check_js_version(ver: version, fix: "15.1R1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.1R1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
