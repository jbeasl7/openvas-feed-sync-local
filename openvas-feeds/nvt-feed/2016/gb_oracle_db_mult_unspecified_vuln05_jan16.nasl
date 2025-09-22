# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807040");
  script_version("2024-10-29T05:05:45+0000");
  script_cve_id("CVE-2014-6546", "CVE-2014-6467", "CVE-2014-6545", "CVE-2014-6453",
                "CVE-2014-6560", "CVE-2014-6455", "CVE-2014-6537", "CVE-2014-6547",
                "CVE-2014-4293", "CVE-2014-4292", "CVE-2014-4291", "CVE-2014-4290",
                "CVE-2014-4297", "CVE-2014-4296", "CVE-2014-6477", "CVE-2014-4310",
                "CVE-2014-6538", "CVE-2014-4295", "CVE-2014-4294", "CVE-2014-6563",
                "CVE-2014-6542", "CVE-2014-4298", "CVE-2014-4299", "CVE-2014-4300",
                "CVE-2014-6452", "CVE-2014-6454", "CVE-2015-0483", "CVE-2015-0457",
                "CVE-2015-4740", "CVE-2015-2629", "CVE-2015-2599", "CVE-2014-6541",
                "CVE-2014-6567", "CVE-2015-0373");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:45 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"creation_date", value:"2016-01-25 14:59:25 +0530 (Mon, 25 Jan 2016)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities -05 (Jan 2016)");

  script_tag(name:"summary", value:"Oracle Database Server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated attackers to affect confidentiality, integrity, and availability
  via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Database Server versions
  11.1.0.7, 11.2.0.3, 11.2.0.4, 12.1.0.1, and 12.1.0.2.");

  script_tag(name:"solution", value:"Apply the patches from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70453");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70514");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70467");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70474");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70482");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70473");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70492");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70536");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70490");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70499");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70500");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70501");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70502");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70504");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70505");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70495");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70498");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70508");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70465");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70515");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70524");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70526");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70527");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70528");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70529");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74079");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74090");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75838");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75851");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75852");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72158");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72134");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72145");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_oracle_database_consolidation.nasl");
  script_mandatory_keys("oracle/database/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

ver = infos["version"];
path = infos["location"];

if(ver =~ "^1[12]") {
  if(version_is_equal(version:ver, test_version:"12.1.0.1") ||
     version_is_equal(version:ver, test_version:"12.1.0.2") ||
     version_is_equal(version:ver, test_version:"11.2.0.3") ||
     version_is_equal(version:ver, test_version:"11.2.0.4") ||
     version_is_equal(version:ver, test_version:"11.1.0.7")) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"Apply the appropriate patch", install_path:path);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
