# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834091");
  script_version("2024-06-26T05:05:39+0000");
  script_cve_id("CVE-2021-34971", "CVE-2021-34970", "CVE-2021-34976", "CVE-2021-34973",
                "CVE-2021-34949", "CVE-2021-34951", "CVE-2021-34954", "CVE-2021-34955",
                "CVE-2021-34956", "CVE-2021-34957", "CVE-2021-34958", "CVE-2021-34959",
                "CVE-2021-34965", "CVE-2021-34960", "CVE-2021-34961", "CVE-2021-34962",
                "CVE-2021-34963", "CVE-2021-34964", "CVE-2021-34966", "CVE-2021-34967",
                "CVE-2021-40326", "CVE-2021-34948", "CVE-2021-34950", "CVE-2021-34953",
                "CVE-2021-34952", "CVE-2021-34968", "CVE-2021-34969", "CVE-2021-34972",
                "CVE-2021-41780", "CVE-2021-41785", "CVE-2021-41783", "CVE-2021-41782",
                "CVE-2021-41784", "CVE-2021-41781", "CVE-2021-34974", "CVE-2021-34975");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-02 12:55:00 +0000 (Fri, 02 Sep 2022)");
  script_tag(name:"creation_date", value:"2024-06-21 11:16:04 +0530 (Fri, 21 Jun 2024)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities (June-7 2024)");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2021-34971: Heap-based Buffer Overflow Remote Code Execution Vulnerability

  - CVE-2021-34970: An information disclosure vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute remote code, disclose information and cause denial of service.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 11.0.0.49893,
  11.0.1.49938, 10.1.5.37672 and prior on Windows.");

  script_tag(name:"solution", value:"Update to version 10.1.6 or 11.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"10.1.5.37672")) {
  fix = "10.1.6";
}

if(version_is_equal(version:vers, test_version:"11.0.0.49893") ||
   version_is_equal(version:vers, test_version:"11.0.1.49938")) {
  fix = "11.1";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

