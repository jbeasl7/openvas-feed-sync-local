# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dokuwiki:dokuwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809084");
  script_version("2024-03-01T14:37:10+0000");
  script_cve_id("CVE-2016-7964", "CVE-2016-7965");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-02 23:09:00 +0000 (Fri, 02 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-11-03 19:22:45 +0530 (Thu, 03 Nov 2016)");
  script_name("DokuWiki Password Reset Address Spoof And SSRF Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_mandatory_keys("dokuwiki/installed");

  script_xref(name:"URL", value:"https://github.com/splitbrain/dokuwiki/issues/1708");
  script_xref(name:"URL", value:"https://github.com/splitbrain/dokuwiki/issues/1709");

  script_tag(name:"summary", value:"DokuWiki is prone to ssrf and password reset address spoof vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The sendRequest method in HTTPClient Class in file '/inc/HTTPClient.php' has
    no way to restrict access to private networks when media file fetching is
    enabled.

  - '$_SERVER[HTTP_HOST]' is used instead of the baseurl setting as part of the
    password-reset URL.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct phishing attacks and to scan port of internal network.");

  script_tag(name:"affected", value:"DokuWiki version 2016-06-26a and older.");

  script_tag(name:"solution", value:"The vendor sees this issue as a won't fix from
  DokuWiki side. Specific deployment hints to mitigate those vulnerabilities are available
  in the referenced github issues.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2016-06-26a" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"Mitigation" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
