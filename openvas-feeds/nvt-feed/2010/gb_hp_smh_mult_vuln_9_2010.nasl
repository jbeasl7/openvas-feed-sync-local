# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:system_management_homepage";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100810");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)");
  script_cve_id("CVE-2010-3009", "CVE-2010-3011", "CVE-2010-3012", "CVE-2010-2068", "CVE-2009-4143",
                "CVE-2009-4018", "CVE-2009-4017", "CVE-2009-3555");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("HP/HPE System Management Homepage (SMH) Multiple Vulnerabilities (HPSBMA02566, HPSBMA02568)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43269");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43208");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-c02512995");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-c02475053");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_hp_smh_http_detect.nasl");
  script_mandatory_keys("hp/smh/detected");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to multiple
  vulnerabilities.");

  script_tag(name:"insight", value:"1. An HTTP response-splitting vulnerability.

  Attackers can leverage this issue to influence or misrepresent how web
  content is served, cached, or interpreted. This could aid in various
  attacks that try to entice client users into a false sense of trust.

  2. An unspecified remote information disclosure vulnerability.

  Remote attackers can exploit this issue to obtain sensitive
  information that may lead to further attacks.

  3. Multiple vulnerabilities in Apache, PHP and SSL");

  script_tag(name:"affected", value:"HP/HPE SMH prior to version 6.2.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"6.2.0.12")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"6.2.0.12");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
