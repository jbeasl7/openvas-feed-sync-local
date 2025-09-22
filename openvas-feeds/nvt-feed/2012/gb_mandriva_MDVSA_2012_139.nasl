# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:139");
  script_oid("1.3.6.1.4.1.25623.1.0.831725");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-08-21 11:46:08 +0530 (Tue, 21 Aug 2012)");
  script_cve_id("CVE-2012-3488", "CVE-2012-3489");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 03:22:42 +0000 (Thu, 15 Feb 2024)");
  script_xref(name:"MDVSA", value:"2012:139");
  script_name("Mandriva Update for postgresql MDVSA-2012:139 (postgresql)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(2011\.0|mes5\.2)");
  script_tag(name:"affected", value:"postgresql on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been discovered and corrected in
  postgresql:

  Prevent access to external files/URLs via contrib/xml2's xslt_process()
  (Peter Eisentraut). libxslt offers the ability to read and write both
  files and URLs through stylesheet commands, thus allowing unprivileged
  database users to both read and write data with the privileges of the
  database server. Disable that through proper use of libxslt's security
  options (CVE-2012-3488). Also, remove xslt_process()'s ability to
  fetch documents and stylesheets from external files/URLs. While this
  was a documented feature, it was long regarded as a bad idea. The
  fix for CVE-2012-3489 broke that capability, and rather than expend
  effort on trying to fix it, we're just going to summarily remove it.

  Prevent access to external files/URLs via XML entity references (Noah
  Misch, Tom Lane). xml_parse() would attempt to fetch external files or
  URLs as needed to resolve DTD and entity references in an XML value,
  thus allowing unprivileged database users to attempt to fetch data
  with the privileges of the database server. While the external data
  wouldn't get returned directly to the user, portions of it could
  be exposed in error messages if the data didn't parse as valid XML.
  And in any case the mere ability to check existence of a file might
  be useful to an attacker (CVE-2012-3489).

  This advisory provides the latest versions of PostgreSQL that is not
  vulnerable to these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"libecpg9.0_6", rpm:"libecpg9.0_6~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpq9.0_5", rpm:"libpq9.0_5~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql9.0", rpm:"postgresql9.0~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql9.0-contrib", rpm:"postgresql9.0-contrib~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql9.0-devel", rpm:"postgresql9.0-devel~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql9.0-docs", rpm:"postgresql9.0-docs~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql9.0-pl", rpm:"postgresql9.0-pl~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql9.0-plperl", rpm:"postgresql9.0-plperl~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql9.0-plpgsql", rpm:"postgresql9.0-plpgsql~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql9.0-plpython", rpm:"postgresql9.0-plpython~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql9.0-pltcl", rpm:"postgresql9.0-pltcl~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql9.0-server", rpm:"postgresql9.0-server~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ecpg9.0_6", rpm:"lib64ecpg9.0_6~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pq9.0_5", rpm:"lib64pq9.0_5~9.0.9~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"libecpg8.3_6", rpm:"libecpg8.3_6~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpq8.3_5", rpm:"libpq8.3_5~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql8.3", rpm:"postgresql8.3~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql8.3-contrib", rpm:"postgresql8.3-contrib~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql8.3-devel", rpm:"postgresql8.3-devel~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql8.3-docs", rpm:"postgresql8.3-docs~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql8.3-pl", rpm:"postgresql8.3-pl~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql8.3-plperl", rpm:"postgresql8.3-plperl~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql8.3-plpgsql", rpm:"postgresql8.3-plpgsql~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql8.3-plpython", rpm:"postgresql8.3-plpython~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql8.3-pltcl", rpm:"postgresql8.3-pltcl~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postgresql8.3-server", rpm:"postgresql8.3-server~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ecpg8.3_6", rpm:"lib64ecpg8.3_6~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pq8.3_5", rpm:"lib64pq8.3_5~8.3.20~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
