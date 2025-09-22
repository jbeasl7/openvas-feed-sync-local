# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:atlas";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112032");
  script_version("2025-02-14T15:39:49+0000");
  script_tag(name:"last_modification", value:"2025-02-14 15:39:49 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-08-31 15:29:09 +0200 (Thu, 31 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-02 11:54:00 +0000 (Sat, 02 Sep 2017)");

  script_cve_id("CVE-2016-8752");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Atlas < 0.8 Access Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_atlas_http_detect.nasl");
  script_mandatory_keys("apache/atlas/detected");

  script_tag(name:"summary", value:"Apache Atlas is prone to an access vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Atlas users can access the webapp directory contents by
  pointing to URIs like /js, /img.");

  script_tag(name:"affected", value:"Apache Atlas versions 0.6.0-incubating, 0.7.0-incubating and
  0.7.1-incubating.");

  script_tag(name:"solution", value:"Update to version 0.8 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/f7435d66b840daa2a38ad1329d639b70f5a9476e7580ae885d422e86@%3Cdev.atlas.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: vers, test_version: "0.6.0") ||
    version_is_equal(version: vers, test_version: "0.7.0") ||
    version_is_equal(version: vers, test_version: "0.7.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "0.8");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
