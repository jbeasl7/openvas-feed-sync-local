# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900715");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1757");
  script_name("Transmission Client CSRF Vulnerability");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/05/21/1");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_transmission_detect.nasl");
  script_mandatory_keys("Transmission/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker hijack the authenticated
  sessions of unspecified users.");
  script_tag(name:"affected", value:"Transmission Client version 1.5 before 1.53 and 1.6 before 1.61");
  script_tag(name:"insight", value:"This flaw is due to Cross-site request forgery error which causes hijacking
  the authentication of unspecified victims via unknown vectors.");
  script_tag(name:"solution", value:"Upgrade to version 1.53 or 1.61.");
  script_tag(name:"summary", value:"Transmission Client is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

transVer = get_kb_item("Transmission/Ver");
if(!transVer)
  exit(0);

if(version_in_range(version:transVer, test_version:"1.5", test_version2:"1.52") ||
   version_in_range(version:transVer, test_version:"1.6", test_version2:"1.60")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
