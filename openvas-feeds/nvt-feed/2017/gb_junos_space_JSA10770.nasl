# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:juniper:junos_space";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106510");
  script_version("2025-01-16T05:37:14+0000");
  script_tag(name:"last_modification", value:"2025-01-16 05:37:14 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-01-12 11:36:50 +0700 (Thu, 12 Jan 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 17:41:00 +0000 (Mon, 03 Jun 2019)");

  script_cve_id("CVE-2016-1762", "CVE-2016-4448", "CVE-2015-5364", "CVE-2016-6515",
                "CVE-2015-8325", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835",
                "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839",
                "CVE-2016-1840", "CVE-2016-5573", "CVE-2016-4449", "CVE-2016-5387",
                "CVE-2015-5366", "CVE-2016-1907", "CVE-2016-3627", "CVE-2016-3705",
                "CVE-2016-4447", "CVE-2015-5307", "CVE-2015-8104", "CVE-2016-6662",
                "CVE-2016-5195", "CVE-2017-2305", "CVE-2017-2306", "CVE-2017-2307",
                "CVE-2017-2308", "CVE-2017-2309", "CVE-2017-2310", "CVE-2017-2311");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper Networks Junos Space Multiple Vulnerabilities (JSA10770)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_space_consolidation.nasl");
  script_mandatory_keys("juniper/junos/space/detected");

  script_tag(name:"summary", value:"Juniper Networks Junos Space is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Junos Space is prone to multiple vulnerabilities in OpenSSH,
  MySQL, Apache HTTP Server, OpenJDK, LibXML, OpenSSL, Linux Kernel and Junos Space itself.");

  script_tag(name:"affected", value:"Juniper Networks Junos Space versions prior to 16.1R1.");

  script_tag(name:"solution", value:"Update to version 16.1R1 or later.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10770");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

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
