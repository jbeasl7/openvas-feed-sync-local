# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:atlas";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144589");
  script_version("2025-02-14T15:39:49+0000");
  script_tag(name:"last_modification", value:"2025-02-14 15:39:49 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"creation_date", value:"2020-09-17 06:52:27 +0000 (Thu, 17 Sep 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-23 16:53:00 +0000 (Wed, 23 Sep 2020)");

  script_cve_id("CVE-2020-13928");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Atlas 2.0.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_atlas_http_detect.nasl");
  script_mandatory_keys("apache/atlas/detected");

  script_tag(name:"summary", value:"Apache Atlas is prone to a cross-site scripting (XSS)
  vulnerability in the basic search functionality.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Atlas version 2.0.0.");

  script_tag(name:"solution", value:"Update to version 2.1.0 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/ra468036f913be41b0c8fea74f91d53e273b0bfa838a4b140a5dcd463%40%3Cuser.atlas.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "2.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
