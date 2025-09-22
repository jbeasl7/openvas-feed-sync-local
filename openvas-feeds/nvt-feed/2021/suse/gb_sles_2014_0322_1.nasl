# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0322.1");
  script_cve_id("CVE-2009-5138", "CVE-2013-1619", "CVE-2013-2116", "CVE-2014-0092");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0322-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0322-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140322-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the SUSE-SU-2014:0322-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The GnuTLS library received a critical security fix and other updates:

 * CVE-2014-0092: The X.509 certificate verification had incorrect error handling, which could lead to broken certificates marked as being valid.
 * CVE-2009-5138: A verification problem in handling V1 certificates could also lead to V1 certificates incorrectly being handled.
 * CVE-2013-2116: The _gnutls_ciphertext2compressed function in lib/gnutls_cipher.c in GnuTLS allowed remote attackers to cause a denial of service (buffer over-read and crash) via a crafted padding length.
 * CVE-2013-1619: Timing attacks against hashing of padding was fixed which might have allowed disclosure of keys. (Lucky13 attack).

Also the following non-security bugs have been fixed:

 * gnutls doesn't like root CAs without Basic Constraints. Permit V1 Certificate Authorities properly
(bnc#760265)
 * memory leak in PSK authentication (bnc#835760)

Security Issue references:

 * CVE-2014-0092
>
 * CVE-2009-5138
>
 * CVE-2013-2116
>
 * CVE-2013-1619
>");

  script_tag(name:"affected", value:"'gnutls' package(s) on SUSE Linux Enterprise Server 11-SP1.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~2.4.1~24.39.49.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-extra26", rpm:"libgnutls-extra26~2.4.1~24.39.49.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls26", rpm:"libgnutls26~2.4.1~24.39.49.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls26-32bit", rpm:"libgnutls26-32bit~2.4.1~24.39.49.1", rls:"SLES11.0SP1"))) {
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
