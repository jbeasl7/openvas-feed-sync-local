# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123892");
  script_cve_id("CVE-2011-5000");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:56 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0884)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0884");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0884.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the ELSA-2012-0884 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.3p1-81]
- fixes in openssh-5.3p1-required-authentications.patch (#657378)

[5.3p1-79]
- fix forward on non-localhost ports with IPv6 (#732955)

[5.3p1-78]
- clear SELinux exec context before exec passwd (#814691)

[5.3p1-77]
- prevent post-auth resource exhaustion (#809938)

[5.3p1-76]
- don't escape backslah in a banner (#809619)

[5.3p1-75]
- fix various issues in openssh-5.3p1-required-authentications.patch (#805901)

[5.3p1-74]
- fix out-of-memory killer patch (#744236)

[5.3p1-73]
- remove openssh-4.3p2-no-v6only.patch (#732955)
- adjust Linux out-of-memory killer (#744236)
- fix sshd init script - check existence of crypto (#797384)
- add RequiredAuthentications[12] (#657378)
- run privsep slave process as the users SELinux context (#798241)

[5.3p1-72]
- drop CAVS test driver (#782091)

[5.3p1-71]
- enable aes-ctr ciphers use the EVP engines from OpenSSL such as the AES-NI (#756929)
- add CAVS test driver for the aes-ctr ciphers (#782091)");

  script_tag(name:"affected", value:"'openssh' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~5.3p1~81.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~5.3p1~81.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~5.3p1~81.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-ldap", rpm:"openssh-ldap~5.3p1~81.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~5.3p1~81.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_ssh_agent_auth", rpm:"pam_ssh_agent_auth~0.9~81.el6", rls:"OracleLinux6"))) {
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
