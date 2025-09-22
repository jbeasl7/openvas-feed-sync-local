# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104181");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2022-05-13 05:48:20 +0000 (Fri, 13 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-20 18:03:00 +0000 (Fri, 20 May 2022)");

  script_cve_id("CVE-2022-29885");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat EncryptInterceptor DoS Vulnerability (May 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web Servers");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS)
  vulnerability.

  This VT has been deprecated and merged into the VT 'Apache Tomcat Clustering DoS Vulnerability (May 2022)'
  (OID: 1.3.6.1.4.1.25623.1.0.104180)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The documentation for the EncryptInterceptor incorrectly stated
  it enabled Tomcat clustering to run over an untrusted network. This was not correct. While the
  EncryptInterceptor does provide confidentiality and integrity protection, it does not protect
  against all risks associated with running over any untrusted network, particularly DoS risks.");

  script_tag(name:"affected", value:"Apache Tomcat 8.5.38 through 8.5.78, 9.0.13 through 9.0.62,
  10.0.0-M1 through 10.0.20 and 10.1.0-M1 to 10.1.0-M14.");

  script_tag(name:"solution", value:"Update to version 10.1.0-M15, 10.0.21, 9.0.63, 8.5.79 or
  later.");

  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.0-M15");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.21");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.63");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.79");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/548bnqoxvp0rqqq2yyj90l0xvwhq087d");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
