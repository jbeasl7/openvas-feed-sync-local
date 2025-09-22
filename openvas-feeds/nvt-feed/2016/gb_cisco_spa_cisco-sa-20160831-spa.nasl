# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:cisco:spa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106217");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-01 13:50:07 +0700 (Thu, 01 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-27 19:04:00 +0000 (Tue, 27 Jun 2023)");

  script_cve_id("CVE-2016-1469");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Small Business SPA3x/5x Series Denial of Service Vulnerability (cisco-sa-20160831-spa)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_spa_voip_device_sip_detect.nasl");
  script_mandatory_keys("cisco/spa_voip/detected");

  script_tag(name:"summary", value:"A vulnerability in the HTTP framework of Cisco Small Business
  SPA300 Series IP Phones, Cisco Small Business SPA500 Series IP Phones, and Cisco SPA51x IP Phones
  could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on
  an affected device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to incorrect handling of malformed
  HTTP traffic. An attacker could exploit this vulnerability by sending crafted HTTP requests to an
  affected device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to deny service continually
  by sending crafted HTTP requests to a phone, resulting in a DoS condition.");

  script_tag(name:"affected", value:"SPA300 Series IP Phones, SPA500 Series IP Phones and SPA51x IP
  Phones.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160831-spa");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (cpe !~ "^cpe:/o:cisco:spa(30|50|51)")
  exit(0);

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "7.5.7.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
