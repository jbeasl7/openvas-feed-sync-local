# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802927");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2012-08-07 13:44:27 +0530 (Tue, 07 Aug 2012)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2011-4358");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle GlassFish Server Expression Evaluation Security Bypass Vulnerability (Jul 2012)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_eclipse_glassfish_http_detect.nasl");
  script_mandatory_keys("eclipse/glassfish/detected");

  script_tag(name:"summary", value:"Oracle GlassFish Server is prone to a security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unspecified error in the application, allows remote
  attackers to bypass certain security restrictions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary script code in the browser of an unsuspecting user in the context of an affected
  application.");

  script_tag(name:"affected", value:"Oracle GlassFish Server version 3.0.1 and 3.1.1.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49956/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50846");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46959/");
  script_xref(name:"URL", value:"http://java.net/jira/browse/JAVASERVERFACES-2247");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2012verbose-392736.html#Oracle%20Sun%20Products%20Suit");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "3.0.1") ||
    version_is_equal(version: version, test_version: "3.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
