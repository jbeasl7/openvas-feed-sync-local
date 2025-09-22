# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_portal";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106199");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-08-25 13:21:11 +0700 (Thu, 25 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2015-7419");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Portal DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_websphere_portal_detect.nasl");
  script_mandatory_keys("ibm_websphere_portal/installed");

  script_tag(name:"summary", value:"IBM WebSphere Portal is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"insight", value:"By sending malicious requests, a remote attacker could exploit this
vulnerability to cause the consumption of all memory resources to cause a denial of service.");

  script_tag(name:"impact", value:"Successful exploitation will lead to a denial of service.");

  script_tag(name:"affected", value:"IBM WebSphere Portal 8.0.0.1 before CF19 and 8.5.0 before CF09");

  script_tag(name:"solution", value:"For 8.5.0 upgrade to Cumulative Fix 09, for 8.0.0.1 upgrade to
Cumulative Fix 19.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21969906");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^8\.5\.0") {
  if (version_is_less(version: version, test_version: "8.5.0.0.19")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.5.0.0 CF19");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^8\.0\.0\.1") {
  if (version_is_less(version: version, test_version: "8.0.0.1.9")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.1 CF9");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
