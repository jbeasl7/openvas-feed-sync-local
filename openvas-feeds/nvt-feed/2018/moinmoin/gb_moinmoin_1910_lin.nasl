# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112392");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-5934");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-29 13:00:00 +0000 (Thu, 29 Nov 2018)");
  script_tag(name:"creation_date", value:"2018-10-16 12:47:11 +0200 (Tue, 16 Oct 2018)");
  script_name("MoinMoin < 1.9.10 Cross-Site Scripting Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moinmoinWiki/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00024.html");
  script_xref(name:"URL", value:"http://moinmo.in/SecurityFixes");
  script_xref(name:"URL", value:"https://github.com/moinwiki/moin-1.9/commit/70955a8eae091cc88fd9a6e510177e70289ec024");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/10/msg00007.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4318");

  script_tag(name:"impact", value:"The vulnerability exists in the link dialogue in GUI editor and allows
  remote attackers to inject arbitrary web script or HTML via unspecified vectors.");
  script_tag(name:"affected", value:"MoinMoin 1.9.9 and prior are vulnerable.");
  script_tag(name:"solution", value:"Update to version 1.9.10 or later. Please see the references for
  more information.");
  script_tag(name:"summary", value:"MoinMoin is prone to a cross-site scripting vulnerability because it
  fails to sufficiently sanitize user-supplied input data.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:moinmo:moinmoin";

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.9.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.9.10" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
