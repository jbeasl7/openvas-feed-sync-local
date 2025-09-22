# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107148");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-04-18 10:44:46 +0200 (Tue, 18 Apr 2017)");
  script_cve_id("CVE-2016-7551");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-25 00:39:00 +0000 (Tue, 25 Apr 2017)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Asterisk Open Source and Certified Asterisk RTP Resource Exhaustion DoS Vulnerability");

  script_tag(name:"summary", value:"Asterisk Open Source and Certified Asterisk are prone to a
  remote denial of service (DoS) vulnerability.

  This VT has been deprecated since this check is already covered in 'Asterisk RTP Resource
  Exhaustion Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.106239).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The overlap dialing feature in chan_sip allows chan_sip to report to
  a device that the number that has been dialed is incomplete and more digits are required. If this functionality
  is used with a device that has performed username/password authentication RTP resources are leaked. This occurs
  because the code fails to release the old RTP resources before allocating new ones in this scenario. If all
  resources are used then RTP port exhaustion will occur and no RTP sessions are able to be set up.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause a denial-of-service condition.");

  script_tag(name:"affected", value:"The following products and versions are vulnerable:

  Digium Asterisk 13 before 13.11.1

  Digium Asterisk 11 before 11.23.1

  Digium Certified Asterisk 13 before 13.8-cert3

  Digium Certified Asterisk 11 before 11.6-cert1");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92888");
  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2016-007.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");

  script_tag(name:"deprecated", value: TRUE);

  exit(0);
}

exit(66);
