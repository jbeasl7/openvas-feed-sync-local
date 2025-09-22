# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sendmail:sendmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100415");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2009-4565");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Sendmail NULL Character CA SSL Certificate Validation Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("SMTP problems");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_sendmail_smtp_detect.nasl");
  script_mandatory_keys("sendmail/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37543");
  script_xref(name:"URL", value:"http://www.sendmail.org/releases/8.14.4");

  script_tag(name:"summary", value:"Sendmail is prone to a security bypass vulnerability because the
  application fails to properly validate the domain name in a signed CA certificate, allowing
  attackers to substitute malicious SSL certificates for trusted ones.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to perform
  man-in-the-middle attacks or impersonate trusted servers, which will aid in further attacks.");

  script_tag(name:"affected", value:"Versions prior to Sendmail 8.14.4 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

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

if(version_is_less(version:vers, test_version:"8.14.4")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.14.4");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
