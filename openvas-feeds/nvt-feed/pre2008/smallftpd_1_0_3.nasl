# SPDX-FileCopyrightText: 2004 Audun Larsen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12072");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0299");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9684");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_name("smallftpd <= 1.0.3 DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Audun Larsen");
  script_family("Denial of Service");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/smallftpd/detected");

  script_tag(name:"summary", value:"smallftpd is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It has been reported that SmallFTPD is prone to a remote denial
  of service vulnerability. This issue is due to the application failing to properly validate user
  input.");

  script_tag(name:"affected", value:"smallftpd version 1.0.3 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);
if(!banner || "smallftpd" >!< banner)
  exit(0);

if(vers = eregmatch(pattern:"^220.*smallftpd (0\..*|1\.0\.[0-3][^0-9])", string:banner, icase:FALSE)) {
  report = report_fixed_ver(installed_version:vers[1], fixed_version:"None");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
