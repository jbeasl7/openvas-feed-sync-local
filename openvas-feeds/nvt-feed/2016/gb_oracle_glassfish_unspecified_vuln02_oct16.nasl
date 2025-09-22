# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809710");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2016-10-21 15:53:33 +0530 (Fri, 21 Oct 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-31 16:49:00 +0000 (Tue, 31 Jan 2017)");

  script_cve_id("CVE-2016-5519", "CVE-2016-5528", "CVE-2017-3250", "CVE-2017-3249",
                "CVE-2017-3247");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle GlassFish Server 2.1.1, 3.0.1, 3.1.2 Multiple Vulnerabilities (Oct 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_eclipse_glassfish_http_detect.nasl");
  script_mandatory_keys("eclipse/glassfish/detected");

  script_tag(name:"summary", value:"Oracle GlassFish Server is prone to multiple unspecified
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to:

  - An unspecified error in 'Java Server Faces' sub-component.

  - Multiple unspecified errors in 'Security' sub-component.

  - An unspecified error in 'Core' sub-component.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote attackers to affect
  confidentiality, integrity and availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle GlassFish Server version 2.1.1, 3.0.1 and 3.1.2.");

  script_tag(name:"solution", value:"Apply patches from the referenced advisory.");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93698");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95478");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95480");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95484");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95483");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "2.1.1") ||
    version_is_equal(version: version, test_version: "3.0.1") ||
    version_is_equal(version: version, test_version: "3.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
