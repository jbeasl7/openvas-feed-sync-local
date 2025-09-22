# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:novell:file_reporter";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801960");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2750");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Novell File Reporter 'SRS' Tag Arbitrary File Deletion Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45071");
  script_xref(name:"URL", value:"http://aluigi.org/adv/nfr_2-adv.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/518632/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/FileReporter/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to delete
arbitrary files.");
  script_tag(name:"affected", value:"Novell File Reporter (NFR) before 1.0.4.2");
  script_tag(name:"insight", value:"The flaw is due to an error in the NFR Agent (NFRAgent.exe)
when handling 'OPERATION'  and 'CMD' commands in the 'SRS' tag and can be
exploited to delete arbitrary files via a specially crafted SRS request
sent to TCP port 3073.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Novell File Reporter is prone to arbitrary file deletion vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"1.0.400.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
