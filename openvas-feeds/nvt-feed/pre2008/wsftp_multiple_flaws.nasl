# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ipswitch:ws_ftp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14598");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2004-1848", "CVE-2004-1883", "CVE-2004-1884", "CVE-2004-1885",
                "CVE-2004-1886");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WS_FTP Server Multiple Vulnerabilities (Nov 2005)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("FTP");
  script_dependencies("gb_progress_ws_ftp_server_consolidation.nasl");
  script_mandatory_keys("progress/ws_ftp/server/detected");

  script_tag(name:"summary", value:"WS_FTP Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A buffer overflow, caused by a vulnerability in the ALLO handler, an attacker can then execute
  arbitrary code

  - A flaw which allow an attacker to gain elevated privileges (SYSTEM level privileges)

  - A local or remote attacker, with write privileges on a directory can create a specially crafted
  file containing a large REST argument and resulting to a denial of service.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9953");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^[0-3]\.|4\.0[^0-9]|4\.0\.[12][^0-9]") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
