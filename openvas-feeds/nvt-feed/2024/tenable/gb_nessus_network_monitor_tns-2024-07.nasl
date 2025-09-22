# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118596");
  script_version("2024-08-01T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-01 05:05:42 +0000 (Thu, 01 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-07-31 14:47:12 +0000 (Wed, 31 Jul 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 15:53:14 +0000 (Tue, 12 Dec 2023)");

  script_cve_id("CVE-2023-28711", "CVE-2023-46218", "CVE-2023-46219", "CVE-2024-25629");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Network Monitor < 6.4.0 Multiple Vulnerabilities (TNS-2024-07)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tenable_nnm_smb_login_detect.nasl");
  script_mandatory_keys("tenable/nessus_network_monitor/detected");

  script_tag(name:"summary", value:"Tenable Nessus Network Monitor is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Several of the third-party components (hyperscan, curl and
  c-ares) were found to contain vulnerabilities, and updated versions have been made available by
  the providers.

  Out of caution and in line with best practice, Tenable has opted to upgrade these components to
  address the potential impact of the issues. Nessus Network Monitor 6.4.0 updates hyperscan to
  version 5.4.2, curl to version 8.6.0, and c-ares to version 1.28.0.");

  script_tag(name:"affected", value:"Tenable Nessus Network Monitor prior to version 6.4.0.");

  script_tag(name:"solution", value:"Update to version 6.4.0 or later.");

  script_xref(name:"URL", value:"https://tenable.com/security/tns-2024-07");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"6.4.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.4.0", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
