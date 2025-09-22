# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123064");
  script_cve_id("CVE-2012-2662");
  script_tag(name:"creation_date", value:"2015-10-06 10:58:54 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-1347)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1347");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1347.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pki-core' package(s) announced via the ELSA-2015-1347 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[9.0.3-43]
- Resolves #1225589 - unable to create rhel 7.1 replica from rhel 6 replica CA because subsystem user does not exist

[9.0.3-42]
- Resolves #1221900 - pki-core: cross-site scripting flaw in the dogtag administration page (port 9180, port 9444) [rhel-6.7]

[9.0.3-41]
- Resolves #1212557 - ipa-server-install fails when configuring CA

[9.0.3-40]
- Resolves #1171848 - IPA - port 9443 (pki-core) is vulnerable to SSLv3 POODLE
 (based upon upstream changes provided by cfu and alee)");

  script_tag(name:"affected", value:"'pki-core' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"pki-ca", rpm:"pki-ca~9.0.3~43.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-common", rpm:"pki-common~9.0.3~43.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-common-javadoc", rpm:"pki-common-javadoc~9.0.3~43.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-core", rpm:"pki-core~9.0.3~43.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-java-tools", rpm:"pki-java-tools~9.0.3~43.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-java-tools-javadoc", rpm:"pki-java-tools-javadoc~9.0.3~43.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-native-tools", rpm:"pki-native-tools~9.0.3~43.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-selinux", rpm:"pki-selinux~9.0.3~43.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-setup", rpm:"pki-setup~9.0.3~43.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-silent", rpm:"pki-silent~9.0.3~43.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-symkey", rpm:"pki-symkey~9.0.3~43.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-util", rpm:"pki-util~9.0.3~43.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pki-util-javadoc", rpm:"pki-util-javadoc~9.0.3~43.el6", rls:"OracleLinux6"))) {
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
