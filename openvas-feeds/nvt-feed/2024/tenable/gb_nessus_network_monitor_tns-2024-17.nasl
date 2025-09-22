# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131090");
  script_version("2024-09-27T15:39:47+0000");
  script_tag(name:"last_modification", value:"2024-09-27 15:39:47 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-25 09:27:12 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 14:28:41 +0000 (Wed, 04 Sep 2024)");

  script_cve_id("CVE-2024-6119", "CVE-2024-45491", "CVE-2024-45492", "CVE-2024-6197",
                "CVE-2024-7264", "CVE-2024-8096", "CVE-2024-34459", "CVE-2024-9158");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Network Monitor < 6.5.0 Multiple Vulnerabilities (TNS-2024-17)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nnm_smb_login_detect.nasl");
  script_mandatory_keys("tenable/nessus_network_monitor/detected");

  script_tag(name:"summary", value:"Tenable Nessus Network Monitor is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Several of the third-party components (OpenSSL, expat, curl,
  and libxml2) were found to contain vulnerabilities, and updated versions have been made available
  by the providers.

  Out of caution and in line with best practice, Tenable has opted to upgrade these components to
  address the potential impact of the issues. Nessus Network Monitor 6.5.0 updates OpenSSL to
  version 3.0.15, expat to version 2.6.3, curl to version 8.10.0, and libxml2 to version 2.13.1.

  Note: One separate vulnerability was discovered directly in Nessus Network Monitor.
  A stored cross site scripting where an authenticated, privileged local attacker could inject
  arbitrary code into the NNM UI via the local CLI (CVE-2024-9158).");

  script_tag(name:"affected", value:"Tenable Nessus Network Monitor prior to version 6.5.0.");

  script_tag(name:"solution", value:"Update to version 6.5.0 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2024-17");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"6.5.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.5.0", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
