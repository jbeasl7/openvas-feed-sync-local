# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802409");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2012-01-05 16:15:38 +0530 (Thu, 05 Jan 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2011-5035");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle GlassFish Server <= 3.1.1 Hash Collision DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_eclipse_glassfish_http_detect.nasl");
  script_mandatory_keys("eclipse/glassfish/detected");

  script_tag(name:"summary", value:"GlassFish Server is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error within a hash generation function
  when hashing form posts and updating a hash table. This can be exploited to cause a hash
  collision resulting in high CPU consumption via a specially crafted form sent in a HTTP POST
  request.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a
  denial of service via a specially crafted form sent in a HTTP POST request.");

  script_tag(name:"affected", value:"Oracle GlassFish version 3.1.1 and prior.");

  script_tag(name:"solution", value:"Apply the updates from the referenced advisory.");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/903934");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51194");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2011-003.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version:"3.1.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
