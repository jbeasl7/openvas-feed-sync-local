# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118126");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2021-20106");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-30 14:49:00 +0000 (Fri, 30 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-02 11:19:14 +0200 (Fri, 02 Jul 2021)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Tenable Nessus Agent < 8.3.0 Privilege Escalation Vulnerability (TNS-2021-13)");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The product contains a privilege escalation vulnerability which
  could allow a Nessus administrator user to upload a specially crafted file that could lead to
  gaining administrator privileges on the Nessus host.");

  script_tag(name:"affected", value:"Tenable Nessus Agent prior to version 8.3.0.");

  script_tag(name:"solution", value:"Update to version 8.3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2021-13");

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
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

if( version_is_less( version:vers, test_version:"8.3.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.3.0", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
