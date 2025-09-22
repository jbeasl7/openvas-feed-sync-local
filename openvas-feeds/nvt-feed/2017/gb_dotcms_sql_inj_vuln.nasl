# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dotcms:dotcms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106616");
  script_version("2024-07-26T15:38:40+0000");
  script_tag(name:"last_modification", value:"2024-07-26 15:38:40 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-02-21 15:43:41 +0700 (Tue, 21 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");

  script_cve_id("CVE-2017-5344");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("dotCMS < 3.6.2 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotcms_http_detect.nasl");
  script_mandatory_keys("dotcms/detected");

  script_tag(name:"summary", value:"dotCMS is prone to a blind SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The findChildrenByFilter() function which is called by the web
  accessible path /categoriesServlet performs string interpolation and direct SQL query execution.
  SQL quote escaping and a keyword blacklist were implemented in a new class, SQLUtil
  (main/java/com/dotmarketing/common/util/SQLUtil.java), as part of the remediation of
  CVE-2016-8902. However, these can be overcome in the case of the q and inode parameters to the
  /categoriesServlet path. Overcoming these controls permits a number of blind boolean SQL
  injection vectors in either parameter. The /categoriesServlet web path can be accessed remotely
  and without authentication in a default dotCMS deployment.");

  script_tag(name:"affected", value:"dotCMS version 3.6.1 and prior.");

  script_tag(name:"solution", value:"Update to version 3.6.2 or later.");

  script_xref(name:"URL", value:"http://dotcms.com/security/SI-39");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
