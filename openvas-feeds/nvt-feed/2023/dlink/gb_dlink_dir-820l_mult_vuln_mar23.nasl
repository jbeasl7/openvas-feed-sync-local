# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-820l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170360");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2023-03-14 10:21:34 +0000 (Tue, 14 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-21 17:33:00 +0000 (Tue, 21 Mar 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2022-34973", "CVE-2023-25279", "CVE-2023-25280", "CVE-2023-25281",
                "CVE-2023-25282", "CVE-2023-25283", "CVE-2024-48150");

  script_name("D-Link DIR-820L Devices Multiple Vulnerabilities (Mar 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-820L devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-34973: Buffer overflow via the nextPage parameter at ping.ccp.

  - CVE-2023-25279: OS Command injection vulnerability allows attackers to escalate privileges to
  root via a crafted payload.

  - CVE-2023-25280: OS Command injection vulnerability allows attackers to escalate privileges to
  root via a crafted payload with the ping_addr parameter to ping.ccp.

  - CVE-2023-25281: A stack overflow vulnerability existing in pingV4Msg component allows attackers
  to cause a denial of service via the nextPage parameter to ping.ccp.

  - CVE-2023-25282: A heap overflow vulnerability allows attackers to cause a denial of service via
  the config.log_to_syslog and log_opt_dropPackets parameters to mydlink_api.ccp.

  - CVE-2023-25283: A stack overflow vulnerability allows attackers to cause a denial of service via
  the reserveDHCP_HostName_1.1.1.0 parameter to lan.asp.

  - CVE-2024-48150: Stack overflow");

  script_tag(name:"affected", value:"D-Link DIR-820L devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-820L reached its End-of-Support Date in 01.11.2017, it is no longer
  supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://github.com/migraine-sudo/D_Link_Vuln/tree/main/cmd%20Inject%20In%20tools_AccountName");
  script_xref(name:"URL", value:"https://github.com/migraine-sudo/D_Link_Vuln/tree/main/stackoverflow%20%20in%20reserveDHCP_HostName_1.1.1.0");
  script_xref(name:"URL", value:"https://github.com/migraine-sudo/D_Link_Vuln/tree/main/cmd%20Inject%20in%20pingV4Msg");
  script_xref(name:"URL", value:"https://github.com/migraine-sudo/D_Link_Vuln/tree/main/stackoverflow%20cancelPing");
  script_xref(name:"URL", value:"https://github.com/migraine-sudo/D_Link_Vuln/tree/main/Permanent%20DDOS%20vulnerability%20in%20emailInfo");
  script_xref(name:"URL", value:"https://github.com/fu37kola/cve/blob/main/D-Link/DIR-820L/D-Link%20DIR-820L%20Stack%20Overflow%20Vulnerability.md");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/pages/product.aspx?id=00c2150966b046b58ba95d8ae3a8f73d");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );
