# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900573");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 14:11:43 +0000 (Fri, 02 Feb 2024)");
  script_cve_id("CVE-2009-1955");
  script_name("Apache APR-Utils XML Parser Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_apache_apr-utils_detect.nasl");
  script_mandatory_keys("Apache/APR-Utils/Ver");

  script_xref(name:"URL", value:"http://www.apache.org/dist/apr/CHANGES-APR-UTIL-1.3");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35253");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=rev&revision=781403");

  script_tag(name:"impact", value:"Attackers can exploit these issues to crash the application
  resulting into a denial of service condition.");

  script_tag(name:"affected", value:"Apache APR-Utils version prior to 1.3.7 on Linux.");

  script_tag(name:"insight", value:"An error in the 'expat XML' parser when processing crafted XML documents
  containing a large number of nested entity references.");

  script_tag(name:"solution", value:"Apply the patch or upgrade to Apache APR-Utils 1.3.7.");

  script_tag(name:"summary", value:"Apache APR-Utils is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

utilsVer = get_kb_item("Apache/APR-Utils/Ver");
if(!utilsVer)
  exit(0);

if(version_is_less(version:utilsVer, test_version:"1.3.7")) {
  report = report_fixed_ver(installed_version:utilsVer, fixed_version:"1.3.7");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);