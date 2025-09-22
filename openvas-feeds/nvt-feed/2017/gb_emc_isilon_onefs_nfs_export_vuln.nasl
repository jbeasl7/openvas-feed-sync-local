# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dell:emc_isilon_onefs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106805");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-05-16 16:14:35 +0700 (Tue, 16 May 2017)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-4979");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EMC Isilon OneFS NFS Export Upgrade Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_emc_isilon_onefs_consolidation.nasl");
  script_mandatory_keys("dell/emc_isilon/onefs/detected");

  script_tag(name:"summary", value:"EMC Isilon OneFS is affected by an NFS export vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"EMC Isilon OneFS is affected by the OneFS NFS Export Upgrade Vulnerability.
  Changing the default export permissions, after having created exports and then upgrading OneFS, can result in
  giving access to users that shouldn't have it, or in prohibiting access to those that should have access.");

  script_tag(name:"affected", value:"EMC Isilon OneFS 7.2.0.x, 7.2.1.0 - 7.2.1.3, 8.0.0.0 - 8.0.0.2 and 8.0.1.0.");

  script_tag(name:"solution", value:"Update to version 7.2.1.4, 8.0.0.3, 8.0.1.1 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2017/May/att-28/ESA-2017-027.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "7.2.0.0"))
  exit(99);

if (version_is_less(version: version, test_version: "7.2.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1.4");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0.0", test_version2: "8.0.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.3");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "8.0.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
