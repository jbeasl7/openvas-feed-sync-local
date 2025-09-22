# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2013:001");
  script_oid("1.3.6.1.4.1.25623.1.0.831761");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-04 12:54:28 +0530 (Fri, 04 Jan 2013)");
  script_cve_id("CVE-2012-6085");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name:"MDVSA", value:"2013:001");
  script_name("Mandriva Update for gnupg MDVSA-2013:001 (gnupg)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(2011\.0|mes5\.2)");
  script_tag(name:"affected", value:"gnupg on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in gnupg:

  Versions of GnuPG <= 1.4.12 are vulnerable to memory access violations
  and public keyring database corruption when importing public keys
  that have been manipulated. An OpenPGP key can be fuzzed in such a
  way that gpg segfaults (or has other memory access violations) when
  importing the key (CVE-2012-6085).

  The updated packages have been patched to correct this issue.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"gnupg", rpm:"gnupg~1.4.11~2.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.0.18~1.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"gnupg", rpm:"gnupg~1.4.9~5.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.0.9~3.2mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
