# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106954");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-07-18 09:09:00 +0700 (Tue, 18 Jul 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-08 01:29:00 +0000 (Sun, 08 Jul 2018)");

  script_cve_id("CVE-2017-7672");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts URLValidator DoS Vulnerability (S2-047) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");

  script_tag(name:"summary", value:"Apache Struts is prone to a denial of service (DoS)
  vulnerability.

  This VT has been deprecated and merged into the VT 'Apache Struts URLValidator DoS Vulnerability
  (S2-047)' (OID: 1.3.6.1.4.1.25623.1.0.106955).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"If an application allows enter an URL in a form field
  and built-in URLValidator is used, it is possible to prepare a special URL which will be
  used to overload server process when performing validation of the URL.");

  script_tag(name:"affected", value:"Struts 2.5 through 2.5.10.1.");

  script_tag(name:"solution", value:"Update to version 2.5.12 or later.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-047");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
