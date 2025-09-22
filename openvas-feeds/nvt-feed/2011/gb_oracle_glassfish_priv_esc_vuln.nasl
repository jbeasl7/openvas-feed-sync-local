# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902286");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:C");

  script_cve_id("CVE-2010-4438");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle Java GlassFish Server Privilege Escalation Vulnerability (Jan 2011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_eclipse_glassfish_http_detect.nasl");
  script_mandatory_keys("eclipse/glassfish/detected");

  script_tag(name:"summary", value:"GlassFish Server is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The issue is caused by an unspecified error related to the Java
  Message Service, which could allow local attackers to disclose or manipulate certain information,
  or create a denial of service condition.");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to affect
  confidentiality and integrity via unknown vectors.");

  script_tag(name:"affected", value:"Oracle GlassFish version 2.1, 2.1.1 and 3.0.1.");

  script_tag(name:"solution", value:"Apply the security updates.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42988");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45890");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64813");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0155");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2011-194091.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "3.0.1") ||
    version_in_range(version: version, test_version: "2.1", test_version2: "2.1.1")) {
  report = report_fixed_ver( installed_version: version, fixed_version: "See references");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
