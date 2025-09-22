# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eucalyptus:eucalyptus";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106512");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-01-12 13:24:55 +0700 (Thu, 12 Jan 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-13 14:15:00 +0000 (Tue, 13 Mar 2018)");

  script_cve_id("CVE-2014-3577", "CVE-2016-8520");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Helion Eucalyptus Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hp_helion_eucalyptus_detect.nasl");
  script_mandatory_keys("hp/helion_eucalyptus/installed");

  script_tag(name:"summary", value:"HP Helion Eucalyptus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"HP Helion Eucalyptus is prone to multiple vulnerabilities:

  - A version of Apache httpclient library shipped with Eucalyptus does not correctly validates server hostname
when checking X.509 certificates. This vulnerability can allow a man-in-the-middle attack to spoof an SSL server
and hijack a connection. (CVE-2014-3577)

  - HP Helion Eucalyptus does not correctly check IAM user's permissions for accessing versioned objects and ACLs.
In some cases, authenticated users with S3 permissions could also access versioned data. (CVE-2016-8520)");

  script_tag(name:"impact", value:"An attacker may hijack a connection or an authenticated user may access
versioned data.");

  script_tag(name:"affected", value:"HP Helion Eucalyptus version 4.3.0 and prior.");

  script_tag(name:"solution", value:"Update to version 4.3.1");

  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05363782");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
