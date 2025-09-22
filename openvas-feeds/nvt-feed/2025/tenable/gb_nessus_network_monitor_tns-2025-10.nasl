# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127891");
  script_version("2025-06-03T05:40:40+0000");
  script_tag(name:"last_modification", value:"2025-06-03 05:40:40 +0000 (Tue, 03 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-05-30 09:27:12 +0000 (Fri, 30 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-23 18:17:52 +0000 (Wed, 23 Apr 2025)");

  script_cve_id("CVE-2023-7256", "CVE-2024-8006", "CVE-2024-8176", "CVE-2024-9143",
                "CVE-2024-9681", "CVE-2024-11053", "CVE-2024-13176", "CVE-2024-50602",
                "CVE-2025-0167", "CVE-2025-0725", "CVE-2025-24916", "CVE-2025-24917",
                "CVE-2025-32414", "CVE-2025-32415");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Network Monitor < 6.5.1 Multiple Vulnerabilities (TNS-2025-10)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nnm_smb_login_detect.nasl");
  script_mandatory_keys("tenable/nessus_network_monitor/detected");

  script_tag(name:"summary", value:"Tenable Nessus Network Monitor is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Several of the third-party components (OpenSSL, expat, curl,
  libpcap, libxml2) were found to contain vulnerabilities, and updated versions have been made
  available by the providers.

  Out of caution and in line with best practice, Tenable has opted to upgrade these components to
  address the potential impact of the issues. Tenable Network Monitor 6.5.1 updates OpenSSL to
  version 3.0.16, expat to version 2.7.0, curl to version 8.12.0, libpcap to version 1.10.5 and
  libxml2 to version 2.13.8 to address the identified vulnerabilities.

  Note: Two separate vulnerabilities were discovered, reported and fixed:

  When installing Tenable Network Monitor to a non-default location on a Windows host, Tenable
  Network Monitor versions prior to 6.5.1 did not enforce secure permissions for sub-directories.
  This could allow for local privilege escalation if users had not secured the directories in the
  non-default installation location. - CVE-2025-24916.

  In Tenable Network Monitor versions prior to 6.5.1 on a Windows host, it was found that a
  non-administrative user could stage files in a local directory to run arbitrary code with SYSTEM
  privileges, potentially leading to local privilege escalation. - CVE-2025-24917.");

  script_tag(name:"affected", value:"Tenable Nessus Network Monitor prior to version 6.5.1.");

  script_tag(name:"solution", value:"Update to version 6.5.1 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2025-10");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"6.5.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.5.1", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
