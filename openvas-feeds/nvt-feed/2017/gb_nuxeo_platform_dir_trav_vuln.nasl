# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nuxeo:platform";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106696");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-27 14:18:27 +0700 (Mon, 27 Mar 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_cve_id("CVE-2017-5869");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nuxeo Platform Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nuxeo_platform_detect.nasl");
  script_mandatory_keys("nuxeo_platform/installed");

  script_tag(name:"summary", value:"Nuxeo Platform is prone to an authenticated directory traversal
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Directory traversal vulnerability in the file import feature allows remote
authenticated users to upload and execute arbitrary JSP code via a .. (dot dot) in the X-File-Name header.");

  script_tag(name:"impact", value:"An authenticated attacker may upload and execute arbitrary JSP code.");

  script_tag(name:"affected", value:"Nuxeo Platform 6.0, 7.1, 7.2 and 7.3.");

  script_tag(name:"solution", value:"Update to version 7.4 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/03/23/6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "6.0", test_version2: "7.3") || version == "lts-2014") {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
