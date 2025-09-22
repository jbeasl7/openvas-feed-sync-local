# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02515878");
  script_oid("1.3.6.1.4.1.25623.1.0.835243");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2011-01-04 15:48:51 +0100 (Tue, 04 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 22:58:00 +0000 (Wed, 09 Oct 2019)");
  script_xref(name:"HPSBUX", value:"02579");
  script_cve_id("CVE-2010-2227", "CVE-2010-1157", "CVE-2009-0783", "CVE-2009-0781", "CVE-2009-0580", "CVE-2009-0033", "CVE-2008-5515");
  script_name("HP-UX Update for Apache Running Tomcat Servlet Engine HPSBUX02579");
  script_tag(name:"summary", value:"The remote host is missing an update for the Apache Running Tomcat Servlet Engine package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("HP-UX Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/hp_hp-ux", "ssh/login/hp_pkgrev", re:"ssh/login/release=HPUX(11\.31|11\.23)");

  script_tag(name:"impact", value:"Remote information disclosure");

  script_tag(name:"affected", value:"Apache Running Tomcat Servlet Engine on HP-UX B.11.23, B.11.31 running HP-UX Apache Web Server Suite v3.12 or
  earlier");

  script_tag(name:"insight", value:"Potential security vulnerabilities have been identified with HP-UX Apache
  Running Tomcat Servlet Engine. These vulnerabilities could be exploited
  remotely to disclose information, allows unauthorized modification, or
  create a Denial of Service (DoS). The Tomcat-based Servlet Engine is
  contained in the HP-UX Apache Web Server Suite.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-hpux.inc");

release = hpux_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "HPUX11.31")
{

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22TOMCAT.TOMCAT", revision:"B.5.5.30.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22TOMCAT.TOMCAT", revision:"B.5.5.30.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}