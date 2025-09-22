# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106873");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-15 11:51:23 +0700 (Thu, 15 Jun 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-16 12:57:00 +0000 (Wed, 16 Oct 2019)");

  script_cve_id("CVE-2016-6087");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM Domino TLS Server Diffie-Hellman Key Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"summary", value:"A vulnerability in the IBM Domino TLS server's Diffie-Hellman parameter
  validation could potentially be exploited in a small subgroup attack which could result in a less secure
  connection. An attacker may be able to exploit this vulnerability to obtain user authentication credentials.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"IBM Domino 8.5.1, 8.5.2, 8.5.3, 9.0 and 9.0.1.");

  script_tag(name:"solution", value:"Update to version 9.0.1 FP8.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22002808");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98794");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if (version_is_greater_equal(version: version, test_version: "8.5.1") &&
    version_is_less(version:version, test_version: "9.0.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.1 FP8");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
