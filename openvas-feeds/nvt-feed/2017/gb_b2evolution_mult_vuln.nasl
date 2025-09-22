# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:b2evolution:b2evolution";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106537");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-24 09:44:44 +0700 (Tue, 24 Jan 2017)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-18 14:31:00 +0000 (Wed, 18 Jan 2017)");

  script_cve_id("CVE-2017-5494", "CVE-2017-5480");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("b2evolution Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_b2evolution_detect.nasl");
  script_mandatory_keys("b2evolution/installed");

  script_tag(name:"summary", value:"b2evolution is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"b2evolution is prone to multiple vulnerabilities:

  - Directory traversal vulnerability in inc/files/files.ctrl.php in allows remote authenticated users to read or
delete arbitrary files by leveraging back-office access to provide a .. (dot dot) in the fm_selected array
parameter. (CVE-2017-5480)

  - Multiple cross-site scripting (XSS) vulnerabilities in the file types table allow remote authenticated users to
inject arbitrary web script or HTML via a .swf file in a comment frame or avatar frame. (CVE-2017-5494)");

  script_tag(name:"affected", value:"b2evolution 6.8.3 and prior.");

  script_tag(name:"solution", value:"Upgrade to version 6.8.4 or later");

  script_xref(name:"URL", value:"https://github.com/b2evolution/b2evolution/issues/35");
  script_xref(name:"URL", value:"https://github.com/b2evolution/b2evolution/issues/34");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.8.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
