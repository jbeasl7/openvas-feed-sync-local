# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122096");
  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1834", "CVE-2011-1835", "CVE-2011-1837", "CVE-2011-3145");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:00 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:03:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Oracle: Security Advisory (ELSA-2011-1241)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1241");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1241.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ecryptfs-utils' package(s) announced via the ELSA-2011-1241 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[82-6.3]
- do not forget to set the group id in mount.ecryptfs_private

[82-6.2]
- fix regression in ecryptfs-setup-private

[82-6.1]
- security fixes:
- privilege escalation via mountpoint race conditions (CVE-2011-1831, CVE-2011-1832)
- race condition when checking source during mount (CVE-2011-1833)
- mtab corruption via improper handling (CVE-2011-1834)
- key poisoning via insecure temp directory handling (CVE-2011-1835)
- arbitrary file overwrite via lock counter race (CVE-2011-1837)");

  script_tag(name:"affected", value:"'ecryptfs-utils' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"ecryptfs-utils", rpm:"ecryptfs-utils~75~5.el5_7.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ecryptfs-utils-devel", rpm:"ecryptfs-utils-devel~75~5.el5_7.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ecryptfs-utils-gui", rpm:"ecryptfs-utils-gui~75~5.el5_7.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"ecryptfs-utils", rpm:"ecryptfs-utils~82~6.el6_1.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ecryptfs-utils-devel", rpm:"ecryptfs-utils-devel~82~6.el6_1.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ecryptfs-utils-python", rpm:"ecryptfs-utils-python~82~6.el6_1.3", rls:"OracleLinux6"))) {
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
