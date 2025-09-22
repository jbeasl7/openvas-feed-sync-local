# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833448");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-3961", "CVE-2023-4091", "CVE-2023-4154", "CVE-2023-42669", "CVE-2023-42670");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 18:48:45 +0000 (Mon, 13 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:22:50 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for samba (SUSE-SU-2023:4046-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4046-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HIS5K3PDKXYGYNMA3DZIC7PFORWTC3JN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the SUSE-SU-2023:4046-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for samba fixes the following issues:

  * CVE-2023-4091: Fixed a bug where a client can truncate file with read-only
      permissions. (bsc#1215904)

  * CVE-2023-42669: Fixed a bug in 'rpcecho' development server which allows
      Denial of Service via sleep() call on AD DC. (bsc#1215905)

  * CVE-2023-42670: Fixed the procedure number which was out of range when
      starting Active Directory Users and Computers. (bsc#1215906)

  * CVE-2023-3961: Fixed an unsanitized client pipe name passed to
      local_np_connect(). (bsc#1215907)

  * CVE-2023-4154: Fixed a bug in dirsync which allows SYSTEM access with only
      'GUID_DRS_GET_CHANGES' right. (bsc#1215908)

  ##");

  script_tag(name:"affected", value:"'samba' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"samba-gpupdate", rpm:"samba-gpupdate~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs", rpm:"samba-winbind-libs~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel", rpm:"samba-devel~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3", rpm:"libsamba-policy0-python3~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-devel", rpm:"libsamba-policy-devel~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap", rpm:"samba-ldb-ldap~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo", rpm:"samba-libs-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctdb-pcp-pmda-debuginfo", rpm:"ctdb-pcp-pmda-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctdb-pcp-pmda", rpm:"ctdb-pcp-pmda~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3-debuginfo", rpm:"samba-python3-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-python3-devel", rpm:"libsamba-policy-python3-devel~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3", rpm:"samba-libs-python3~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap-debuginfo", rpm:"samba-ldb-ldap-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctdb-debuginfo", rpm:"ctdb-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-debuginfo", rpm:"samba-libs-python3-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test-debuginfo", rpm:"samba-test-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-tool", rpm:"samba-tool~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctdb", rpm:"ctdb~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-debuginfo", rpm:"samba-client-libs-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo", rpm:"samba-winbind-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo", rpm:"samba-client-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-debuginfo", rpm:"libsamba-policy0-python3-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-debuginfo", rpm:"samba-winbind-libs-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3", rpm:"samba-python3~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test", rpm:"samba-test~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel-32bit", rpm:"samba-devel-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-32bit", rpm:"samba-client-libs-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit", rpm:"samba-client-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-32bit-debuginfo", rpm:"samba-client-libs-32bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-32bit-debuginfo", rpm:"samba-libs-python3-32bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-32bit-debuginfo", rpm:"libsamba-policy0-python3-32bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit-debuginfo", rpm:"samba-client-32bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-32bit-debuginfo", rpm:"samba-winbind-libs-32bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-32bit", rpm:"samba-libs-python3-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit-debuginfo", rpm:"samba-libs-32bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-32bit", rpm:"samba-winbind-libs-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-32bit", rpm:"libsamba-policy0-python3-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ceph-debuginfo", rpm:"samba-ceph-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ceph", rpm:"samba-ceph~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-64bit-debuginfo", rpm:"samba-winbind-libs-64bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-64bit", rpm:"samba-winbind-libs-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-64bit-debuginfo", rpm:"samba-libs-64bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-64bit-debuginfo", rpm:"libsamba-policy0-python3-64bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-64bit", rpm:"samba-client-libs-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-64bit", rpm:"libsamba-policy0-python3-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel-64bit", rpm:"samba-devel-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-64bit-debuginfo", rpm:"samba-client-libs-64bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-64bit", rpm:"samba-libs-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-64bit", rpm:"samba-client-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-64bit-debuginfo", rpm:"samba-client-64bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-64bit-debuginfo", rpm:"samba-libs-python3-64bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-64bit", rpm:"samba-libs-python3-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-gpupdate", rpm:"samba-gpupdate~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs", rpm:"samba-winbind-libs~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel", rpm:"samba-devel~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3", rpm:"libsamba-policy0-python3~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-devel", rpm:"libsamba-policy-devel~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap", rpm:"samba-ldb-ldap~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo", rpm:"samba-libs-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctdb-pcp-pmda-debuginfo", rpm:"ctdb-pcp-pmda-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctdb-pcp-pmda", rpm:"ctdb-pcp-pmda~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3-debuginfo", rpm:"samba-python3-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-python3-devel", rpm:"libsamba-policy-python3-devel~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3", rpm:"samba-libs-python3~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap-debuginfo", rpm:"samba-ldb-ldap-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctdb-debuginfo", rpm:"ctdb-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-debuginfo", rpm:"samba-libs-python3-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test-debuginfo", rpm:"samba-test-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-tool", rpm:"samba-tool~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctdb", rpm:"ctdb~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-debuginfo", rpm:"samba-client-libs-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo", rpm:"samba-winbind-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo", rpm:"samba-client-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-debuginfo", rpm:"libsamba-policy0-python3-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-debuginfo", rpm:"samba-winbind-libs-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3", rpm:"samba-python3~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-test", rpm:"samba-test~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel-32bit", rpm:"samba-devel-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-32bit", rpm:"samba-client-libs-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit", rpm:"samba-client-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-32bit-debuginfo", rpm:"samba-client-libs-32bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-32bit-debuginfo", rpm:"samba-libs-python3-32bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-32bit-debuginfo", rpm:"libsamba-policy0-python3-32bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-32bit-debuginfo", rpm:"samba-client-32bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-32bit-debuginfo", rpm:"samba-winbind-libs-32bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-32bit", rpm:"samba-libs-python3-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit-debuginfo", rpm:"samba-libs-32bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-32bit", rpm:"samba-winbind-libs-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-32bit", rpm:"libsamba-policy0-python3-32bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ceph-debuginfo", rpm:"samba-ceph-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ceph", rpm:"samba-ceph~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-64bit-debuginfo", rpm:"samba-winbind-libs-64bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-64bit", rpm:"samba-winbind-libs-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-64bit-debuginfo", rpm:"samba-libs-64bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-64bit-debuginfo", rpm:"libsamba-policy0-python3-64bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-64bit", rpm:"samba-client-libs-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-64bit", rpm:"libsamba-policy0-python3-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel-64bit", rpm:"samba-devel-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-64bit-debuginfo", rpm:"samba-client-libs-64bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-64bit", rpm:"samba-libs-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-64bit", rpm:"samba-client-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-64bit-debuginfo", rpm:"samba-client-64bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-64bit-debuginfo", rpm:"samba-libs-python3-64bit-debuginfo~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-64bit", rpm:"samba-libs-python3-64bit~4.17.9+git.421.abde31ca5c2~150500.3.11.1", rls:"openSUSELeap15.5"))) {
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