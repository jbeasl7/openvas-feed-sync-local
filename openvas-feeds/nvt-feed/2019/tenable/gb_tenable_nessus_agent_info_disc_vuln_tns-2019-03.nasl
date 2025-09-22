# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107028");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2019-1559");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-24 19:47:00 +0000 (Thu, 24 Mar 2022)");
  script_tag(name:"creation_date", value:"2019-06-26 15:26:25 +0200 (Wed, 26 Jun 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Tenable Nessus Agent < 7.4.0 Information Disclosure Vulnerability in OpenSSL (TNS-2019-03)");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to an information disclosure vulnerability in OpenSSL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An information disclosure vulnerability exists in the third party component OpenSSL.");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker may be able to:

  - obtain sensitive information, caused by the failure to immediately close the TCP connection after
  the hosts encounter a zero-length record with valid padding (CVE-2019-1559).");

  script_tag(name:"affected", value:"Tenable Nessus Agent versions prior to version 7.4.0.");

  script_tag(name:"solution", value:"Update to version 7.4.0 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2019-03");
  script_xref(name:"URL", value:"https://www.openssl.org/news/cl102.txt");

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_tenable_nessus_agent_detect_smb.nasl");
  script_mandatory_keys("tenable/nessus_agent/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"7.4.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.4.0", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
