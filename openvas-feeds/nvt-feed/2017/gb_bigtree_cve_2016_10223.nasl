# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bigtreecms:bigtree_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140164");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2016-10223");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-16 13:34:00 +0000 (Thu, 16 Feb 2017)");
  script_tag(name:"creation_date", value:"2017-02-17 10:34:05 +0100 (Fri, 17 Feb 2017)");
  script_name("BigTree CMS Potential XSS Attack");

  script_tag(name:"summary", value:"BigTree CMS is prone to an XSS vulnerability due to an improper validation of input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists due to insufficient filtration of user-supplied data in the `id` HTTP GET
  parameter passed to the 'core/admin/adjax/dashboard/check-module-integrity.php' URL.");

  script_tag(name:"impact", value:"An attacker could execute arbitrary HTML and script code in a browser in the context of the vulnerable website.");

  script_tag(name:"affected", value:"BigTree CMS before 4.2.15.");

  script_tag(name:"solution", value:"Update to version 4.2.15 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_bigtree_detect.nasl");
  script_mandatory_keys("bigtree_cms/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(port:port, cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"4.2.15")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.2.15");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
