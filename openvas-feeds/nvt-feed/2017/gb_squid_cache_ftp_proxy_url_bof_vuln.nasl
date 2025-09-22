# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811542");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2002-0068");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-28 12:44:20 +0530 (Fri, 28 Jul 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Squid 2.0 < 2.4 STABLE4 FTP Proxy URL Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"Squid is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a buffer overflow error
  in the Squid server's FTP URL handling.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to crash the squid process or execute arbitrary code. To exploit
  this vulnerability, and attacker must have the ability to use the Squid
  cache, and additionally be able to proxy FTP requests through the server.");

  script_tag(name:"affected", value:"Squid version 2.0 through 2.4 STABLE3.");

  script_tag(name:"solution", value:"Update to version 2.4 STABLE4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v2/2.4/bugs");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4148");
  script_xref(name:"URL", value:"https://www.symantec.com/security_response/attacksignatures/detail.jsp?asid=24823");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_squid_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("squid/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^2\.") {
  if(revcomp(a: version, b: "2.4.STABLE4") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.4.STABLE4");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
