# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131107");
  script_cve_id("CVE-2015-2695", "CVE-2015-2696", "CVE-2015-2697");
  script_tag(name:"creation_date", value:"2015-11-08 11:02:04 +0000 (Sun, 08 Nov 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0436)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0436");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0436.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17078");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170683.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the MGASA-2015-0436 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated krb5 packages fix security vulnerabilities:

In MIT krb5 1.5 and later, applications which call
gss_inquire_context() on a partially-established SPNEGO context can
cause the GSS-API library to read from a pointer using the wrong type,
generally causing a process crash. This bug may go unnoticed, because
the most common SPNEGO authentication scenario establishes the context
after just one call to gss_accept_sec_context(). Java server
applications using the native JGSS provider are vulnerable to this
bug. A carefully crafted SPNEGO packet might allow the
gss_inquire_context() call to succeed with attacker-determined
results, but applications should not make access control decisions
based on gss_inquire_context() results prior to context establishment
(CVE-2015-2695).

In MIT krb5 1.9 and later, applications which call
gss_inquire_context() on a partially-established IAKERB context can
cause the GSS-API library to read from a pointer using the wrong type,
generally causing a process crash. Java server applications using the
native JGSS provider are vulnerable to this bug. A carefully crafted
IAKERB packet might allow the gss_inquire_context() call to succeed
with attacker-determined results, but applications should not make
access control decisions based on gss_inquire_context() results prior
to context establishment (CVE-2015-2696).

In MIT krb5 1.7 and later, an authenticated attacker may be able to
cause a KDC to crash using a TGS request with a large realm field
beginning with a null byte. If the KDC attempts to find a referral to
answer the request, it constructs a principal name for lookup using
krb5_build_principal() with the requested realm. Due to a bug in this
function, the null byte causes only one byte be allocated for the
realm field of the constructed principal, far less than its length.
Subsequent operations on the lookup principal may cause a read beyond
the end of the mapped memory region, causing the KDC process to crash
(CVE-2015-2697).");

  script_tag(name:"affected", value:"'krb5' package(s) on Mageia 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.12.2~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.12.2~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.12.2~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.12.2~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.12.2~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krb53", rpm:"lib64krb53~1.12.2~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krb53-devel", rpm:"lib64krb53-devel~1.12.2~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrb53", rpm:"libkrb53~1.12.2~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrb53-devel", rpm:"libkrb53-devel~1.12.2~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
