# SPDX-FileCopyrightText: 2003 StrongHoldNet
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sendmail:sendmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11321");
  script_version("2024-01-10T05:05:17+0000");
  script_cve_id("CVE-2002-1165", "CVE-2002-1337");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Sendmail 8.8.8 - 8.12.7 Double Pipe Access Validation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 StrongHoldNet");
  script_family("SMTP problems");
  script_dependencies("gb_sendmail_smtp_detect.nasl");
  script_mandatory_keys("sendmail/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210129015957/https://www.securityfocus.com/bid/5845/");

  script_tag(name:"summary", value:"Sendmail is prone to a double pipe access validation
  vulnerability.");

  script_tag(name:"insight", value:"smrsh (supplied by Sendmail) is designed to prevent the
  execution of commands outside of the restricted environment. However, when commands are entered
  using either double pipes or a mixture of dot and slash characters, a user may be able to bypass
  the checks performed by smrsh. This can lead to the execution of commands outside of the
  restricted environment.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Sendmail version 8.8.8 through 8.12.7.");

  script_tag(name:"solution", value:"Update to version 8.12.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"8.8.8", test_version2:"8.12.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.12.8");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
