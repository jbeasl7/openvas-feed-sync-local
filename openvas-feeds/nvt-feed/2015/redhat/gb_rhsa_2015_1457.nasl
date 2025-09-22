# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871406");
  script_version("2024-03-21T05:06:54+0000");
  script_cve_id("CVE-2014-8155", "CVE-2015-0282", "CVE-2015-0294");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 15:24:00 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-07-23 06:26:16 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for gnutls RHSA-2015:1457-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The GnuTLS library provides support for cryptographic algorithms and for
protocols such as Transport Layer Security (TLS).

It was found that GnuTLS did not check activation and expiration dates of
CA certificates. This could cause an application using GnuTLS to
incorrectly accept a certificate as valid when its issuing CA is already
expired. (CVE-2014-8155)

It was found that GnuTLS did not verify whether a hashing algorithm listed
in a signature matched the hashing algorithm listed in the certificate.
An attacker could create a certificate that used a different hashing
algorithm than it claimed, possibly causing GnuTLS to use an insecure,
disallowed hashing algorithm during certificate verification.
(CVE-2015-0282)

It was discovered that GnuTLS did not check if all sections of X.509
certificates indicate the same signature algorithm. This flaw, in
combination with a different flaw, could possibly lead to a bypass of the
certificate signature check. (CVE-2015-0294)

The CVE-2014-8155 issue was discovered by Marcel Kolaja of Red Hat.
The CVE-2015-0282 and CVE-2015-0294 issues were discovered by Nikos
Mavrogiannopoulos of the Red Hat Security Technologies Team.

This update also fixes the following bug:

  * Previously, under certain circumstances, the certtool utility could
generate X.509 certificates which contained a negative modulus.
Consequently, such certificates could have interoperation problems with the
software using them. The bug has been fixed, and certtool no longer
generates X.509 certificates containing a negative modulus. (BZ#1036385)

Users of gnutls are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"gnutls on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1457-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00034.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~2.8.5~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-debuginfo", rpm:"gnutls-debuginfo~2.8.5~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~2.8.5~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-utils", rpm:"gnutls-utils~2.8.5~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
