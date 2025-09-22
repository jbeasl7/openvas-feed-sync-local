# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kodi:kodi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107276");
  script_version("2025-09-09T05:38:49+0000");
  # nb: While the CVEs are also covered via some LSCs these are not directly addressing Kodi but
  # some indirect dependencies / libraries and thus we don't need a low QoD VT for this.
  script_cve_id("CVE-2015-3885", "CVE-2017-8314");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-12-14 14:23:07 +0100 (Thu, 14 Dec 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_name("Kodi < 17.2 Multiple Vulnerabilities (Jun 2017)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_kodi_web_server_detect.nasl");
  script_mandatory_keys("Kodi/WebServer/installed");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210124055135/http://www.securityfocus.com/bid/98668");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201706-17");

  script_tag(name:"summary", value:"Multiple vulnerabilities have been found in Kodi, the worst
  of which could allow remote attackers to execute arbitrary code.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote attackers may use a specially crafted request with
  directory-traversal sequences (&#39 ../&#39 ) to retrieve sensitive information and modify
  arbitrary files. This may aid in further attacks.");

  script_tag(name:"impact", value:"A remote attacker could entice a user to open a specially
  crafted image file using Kodi, possibly resulting in a Denial of Service condition.
  Furthermore, a remote attacker could entice a user process a specially crafted ZIP file
  containing subtitles using Kodi, possibly resulting in execution of arbitrary code with
  the privileges of the process or a Denial of Service condition.");

  script_tag(name:"affected", value:"Kodi versions 17.1 and prior.");

  script_tag(name:"solution", value:"Update to version 17.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"17.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"17.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
