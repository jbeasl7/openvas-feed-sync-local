# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:atlas";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112031");
  script_version("2025-02-14T15:39:49+0000");
  script_tag(name:"last_modification", value:"2025-02-14 15:39:49 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-08-31 14:16:09 +0200 (Thu, 31 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-06 01:29:00 +0000 (Wed, 06 Sep 2017)");

  script_cve_id("CVE-2017-3150", "CVE-2017-3151", "CVE-2017-3152", "CVE-2017-3153",
                "CVE-2017-3154", "CVE-2017-3155");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Atlas < 0.7.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_atlas_http_detect.nasl");
  script_mandatory_keys("apache/atlas/detected");

  script_tag(name:"summary", value:"Apache Atlas is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Atlas versions 0.6.0-incubating and
  0.7.0-incubating.");

  script_tag(name:"solution", value:"Update to version 0.7.1 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/4a4fef91e067fd0d9da569e30867c1fa65e2a0520acde71ddefee0ea@%3Cdev.atlas.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: vers, test_version: "0.6.0") ||
    version_is_equal(version: vers, test_version: "0.7.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "0.7.1");
  security_message(port: port, data:report);
  exit(0);
}

exit(99);
