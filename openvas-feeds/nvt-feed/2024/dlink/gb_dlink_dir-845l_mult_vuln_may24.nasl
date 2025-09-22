# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-845l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170801");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-08-09 13:55:36 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2024-29366", "CVE-2024-29385", "CVE-2024-33110", "CVE-2024-33111",
                "CVE-2024-33112", "CVE-2024-33113");

  script_name("D-Link DIR-845L Devices Multiple Vulnerabilities (May 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-845L devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-29366: Command injection in the cgibin binary

  - CVE-2024-29385: Unauthenticated remote code execution in the cgibin binary via soapcgi_main
  function

  - CVE-2024-33110: Permission bypass via the getcfg.php component

  - CVE-2024-33111: Cross-site scripting (XSS) via /htdocs/webinc/js/bsc_sms_inbox.php

  - CVE-2024-33112: Command injection via the hnap_main()func

  - CVE-2024-33113: Information disclosurey via bsc_sms_inbox.php");

  script_tag(name:"affected", value:"D-Link DIR-845L devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-845L reached its End-of-Support Date in 03.01.2020, it is no longer
  supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://github.com/20Yiju/DLink/blob/master/DIR-845L/CI.md");
  script_xref(name:"URL", value:"https://github.com/songah119/Report/blob/main/CI-1.md");
  script_xref(name:"URL", value:"https://web.archive.org/web/20240508095239/https://github.com/yj94/Yj_learning/blob/main/Week16/D-LINK-POC.md");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );
