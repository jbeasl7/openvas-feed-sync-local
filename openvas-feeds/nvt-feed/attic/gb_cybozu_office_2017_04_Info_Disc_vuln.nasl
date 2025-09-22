# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107151");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-04-24 08:56:53 +0200 (Mon, 24 Apr 2017)");
  script_cve_id("CVE-2016-4871");

  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-20 16:23:00 +0000 (Thu, 20 Apr 2017)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Cybozu Office CVE-2016-4871 DoS Vulnerability");
  script_tag(name:"summary", value:"Cybozu Office is prone to a denial of service (DoS)
  vulnerability.

  This VT has been deprecated as a duplicate of the VT 'Cybozu Office CVE-2016-4871 Denial of
  Service Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.107150).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation of the issue will cause excessive system
  resource consumption, resulting in a denial-of-service condition.");

  script_tag(name:"affected", value:"Cybozu Office 9.0.0 through 10.4.0 are vulnerable");
  script_tag(name:"solution", value:"Update to Cybozu Office 10.4.0.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97716");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");

  script_family("Web application abuses");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
