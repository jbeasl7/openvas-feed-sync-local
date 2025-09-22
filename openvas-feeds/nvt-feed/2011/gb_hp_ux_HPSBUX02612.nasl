# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02579879");
  script_oid("1.3.6.1.4.1.25623.1.0.835247");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-01-04 15:48:51 +0100 (Tue, 04 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 14:11:43 +0000 (Fri, 02 Feb 2024)");
  script_xref(name:"HPSBUX", value:"02612");
  script_cve_id("CVE-2010-1452", "CVE-2009-1956", "CVE-2009-1955", "CVE-2009-1891", "CVE-2009-1890", "CVE-2009-1195", "CVE-2009-0023", "CVE-2007-6203", "CVE-2006-3918");
  script_name("HP-UX Update for Apache-based Web Server HPSBUX02612");
  script_tag(name:"summary", value:"The remote host is missing an update for the Apache-based Web Server package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("HP-UX Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/hp_hp-ux", "ssh/login/hp_pkgrev", re:"ssh/login/release=HPUX(11\.31|11\.23|11\.11)");

  script_tag(name:"impact", value:"Local information disclosure, increase of privilege, remote Denial of Service (DoS)");

  script_tag(name:"affected", value:"Apache-based Web Server on HP-UX B.11.11, B.11.23 and B.11.31 running Apache-based Web Server prior to
  v2.0.63.01 HP-UX Apache-based Web Server v2.0.63.01 is contained in HP-UX
  Web Server Suite v.2.32");

  script_tag(name:"insight", value:"Potential security vulnerabilities have been identified with HP-UX
  Apache-based Web Server. These vulnerabilities could be exploited locally to
  disclose information, increase privilege or remotely create a Denial of
  Service (DoS).");

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

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.APACHE", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.APACHE2", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.AUTH_LDAP", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.AUTH_LDAP2", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.MOD_JK", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.MOD_JK2", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.MOD_PERL", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.MOD_PERL2", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.PHP", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.PHP2", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.WEBPROXY", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE2", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.AUTH_LDAP", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.AUTH_LDAP2", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_JK", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_JK2", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_PERL", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_PERL2", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP2", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.WEBPROXY", revision:"B.2.0.63.01", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.APACHE", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.APACHE2", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.AUTH_LDAP", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.AUTH_LDAP2", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.MOD_JK", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.MOD_JK2", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.MOD_PERL", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.MOD_PERL2", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.PHP", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.PHP2", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.WEBPROXY", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE2", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.AUTH_LDAP", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.AUTH_LDAP2", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_JK", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_JK2", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_PERL", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_PERL2", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP2", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.WEBPROXY", revision:"B.2.0.63.01", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE", revision:"B.2.0.63.01", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE2", revision:"B.2.0.63.01", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.AUTH_LDAP", revision:"B.2.0.63.01", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.AUTH_LDAP2", revision:"B.2.0.63.01", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_JK", revision:"B.2.0.63.01", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_JK2", revision:"B.2.0.63.01", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_PERL", revision:"B.2.0.63.01", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_PERL2", revision:"B.2.0.63.01", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP", revision:"B.2.0.63.01", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP2", revision:"B.2.0.63.01", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.WEBPROXY", revision:"B.2.0.63.01", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
