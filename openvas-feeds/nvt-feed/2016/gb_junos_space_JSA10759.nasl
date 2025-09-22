# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:juniper:junos_space";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140019");
  script_version("2025-01-16T05:37:14+0000");
  script_tag(name:"last_modification", value:"2025-01-16 05:37:14 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-10-26 14:51:46 +0200 (Wed, 26 Oct 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:17:00 +0000 (Tue, 16 Aug 2022)");

  script_cve_id("CVE-2016-0703", "CVE-2016-0800", "CVE-2016-2108", "CVE-2016-6304",
                "CVE-2015-3194", "CVE-2015-3195", "CVE-2016-0704", "CVE-2015-3197",
                "CVE-2016-0702", "CVE-2016-0797", "CVE-2016-0799", "CVE-2016-2105",
                "CVE-2016-2106", "CVE-2016-2109", "CVE-2016-6303", "CVE-2016-2179",
                "CVE-2016-2182", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-6302",
                "CVE-2016-2177", "CVE-2016-2178", "CVE-2016-6306");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper Networks Junos Space Multiple Vulnerabilities (JSA10759)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_space_consolidation.nasl");
  script_mandatory_keys("juniper/junos/space/detected");

  script_tag(name:"summary", value:"Juniper Networks Junos Space is prone to multiple
  vulnerabilities in OpenSSL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The OpenSSL project has published a set of security advisories
  for vulnerabilities resolved in the OpenSSL library in December 2015, March, May, June, August
  and September 2016. Junos Space is potentially affected by many of these issues.");

  script_tag(name:"affected", value:"Juniper Networks Junos Space versions prior to 16.1R1.");

  script_tag(name:"solution", value:"Update to version 16.1R1 or later.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10759");

  exit(0);
}

include("host_details.inc");
include("junos.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(version);

if (check_js_version(ver: version, fix: "16.1R1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.1R1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
