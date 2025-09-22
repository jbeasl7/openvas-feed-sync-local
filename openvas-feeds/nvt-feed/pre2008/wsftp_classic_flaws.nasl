# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ipswitch:ws_ftp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14599");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-1999-0017");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WS FTP Server Session Hijacking Vulnerability (Nov 2005)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("FTP");
  script_dependencies("gb_progress_ws_ftp_server_consolidation.nasl");
  script_mandatory_keys("progress/ws_ftp/server/detected");

  script_tag(name:"summary", value:"WS_FTP server is prone to session hijacking during passive
  connections and to a FTP bounce attack when a user submits a specially crafted FTP command.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6051");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^[0-2]\.|3\.(0\.|1\.[0-3][^0-9])") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
