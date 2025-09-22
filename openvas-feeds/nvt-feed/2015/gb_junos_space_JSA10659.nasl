# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:juniper:junos_space";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105413");
  script_version("2025-01-16T05:37:14+0000");
  script_tag(name:"last_modification", value:"2025-01-16 05:37:14 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-10-19 13:03:28 +0200 (Mon, 19 Oct 2015)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-28 16:40:00 +0000 (Tue, 28 Jul 2020)");

  script_cve_id("CVE-2014-0460", "CVE-2014-0423", "CVE-2014-4264", "CVE-2014-0411",
                "CVE-2014-0453", "CVE-2014-4244", "CVE-2014-4263", "CVE-2012-2110",
                "CVE-2012-2333", "CVE-2014-0224", "CVE-2011-4576", "CVE-2011-4619",
                "CVE-2012-0884", "CVE-2013-0166", "CVE-2011-4109", "CVE-2013-0169",
                "CVE-2013-5908");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper Networks Junos Space Multiple Vulnerabilities (JSA10659)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_space_consolidation.nasl");
  script_mandatory_keys("juniper/junos/space/detected");

  script_tag(name:"summary", value:"Juniper Networks Junos Space is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Junos Space release 14.1R1 addresses multiple vulnerabilities
  in prior releases with updated third party software components. The following is a list of
  software upgraded:

  - OpenJDK runtime 1.7.0 update_45 was upgraded to 1.7.0 update_65.

  - OpenSSL CentOS package was upgraded from 0.9.8e-20 to 0.9.8e-27.el5.");

  script_tag(name:"affected", value:"Junos Space and JA1500, JA2500 (Junos Space Appliance) with
  Junos Space 13.3 and earlier releases.");

  script_tag(name:"solution", value:"Update to version 14.1R1 or later.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10659");

  exit(0);
}

include("host_details.inc");
include("junos.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(version);

if (check_js_version(ver: version, fix: "14.1R1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.1R1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
