# SPDX-FileCopyrightText: 2003 Xue Yong Zhi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sendmail:sendmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11351");
  script_version("2024-01-10T05:05:17+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1146");
  script_cve_id("CVE-2000-0319");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Sendmail < 8.10.0 mail.local DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Xue Yong Zhi");
  script_family("SMTP problems");
  script_dependencies("gb_sendmail_smtp_detect.nasl");
  script_mandatory_keys("sendmail/detected");

  script_tag(name:"summary", value:"mail.local in the remote Sendmail server, according to its
  version number, does not properly identify the '.\n' string which identifies the end of message
  text, which allows a remote attacker to cause a denial of service or corrupt mailboxes via a
  message line that is 2047 characters long and ends in '.\n'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to versions 8.10.0 or later, or install a vendor
  supplied patch.");

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

# nb: 5.58, 5.59, 8.6.*, 8.7.*, 8.8.*, 8.9.1, 8.9.3(icat.nist.gov)
# nb: bugtrap id 1146 only said 8.9.3, I guess it want to say 8.9.3 and older
if(vers =~ "^(5\.5[89]|8\.([6-8]|[6-8]\.[0-9]+)|8\.9\.[1-3])$") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.10.0");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
