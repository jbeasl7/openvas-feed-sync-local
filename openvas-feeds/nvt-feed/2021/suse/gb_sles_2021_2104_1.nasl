# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2104.1");
  script_cve_id("CVE-2021-25315", "CVE-2021-31607");
  script_tag(name:"creation_date", value:"2021-06-23 06:40:31 +0000 (Wed, 23 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-04 20:24:06 +0000 (Tue, 04 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2104-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2104-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212104-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186674");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-June/009055.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Salt' package(s) announced via the SUSE-SU-2021:2104-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

salt:

Update to Salt release version 3002.2 (jsc#ECO-3212, jsc#SLE-18033, jsc#SLE-18028)

- Check if dpkgnotify is executable (bsc#1186674)
- Drop support for Python2. Obsoletes `python2-salt` package (jsc#SLE-18028)
- Virt module updates
 * network: handle missing ipv4 netmask attribute
 * more network support
 * PCI/USB host devices passthrough support
- Set distro requirement to oldest supported version in requirements/base.txt
- Bring missing part of async batch implementation back (bsc#1182382, CVE-2021-25315)
- Always require python3-distro (bsc#1182293)
- Remove deprecated warning that breaks minion execution when 'server_id_use_crc' opts is missing
- Fix pkg states when DEB package has 'all' arch
- Do not force beacons configuration to be a list.
- Remove msgpack < 1.0.0 from base requirements (bsc#1176293)
- Msgpack support for version >= 1.0.0 (bsc#1171257)
- Fix issue parsing errors in ansiblegate state module
- Prevent command injection in the snapper module (bsc#1185281, CVE-2021-31607)
- Transactional_update: detect recursion in the executor
- Add subpackage salt-transactional-update (jsc#SLE-18033)
- Remove duplicate directories from specfile
- Improvements on 'ansiblegate' module (bsc#1185092):
 * New methods: ansible.targets / ansible.discover_playbooks
- Add support for Alibaba Cloud Linux 2 (Aliyun Linux)
- Regression fix of salt-ssh on processing targets
- Update target fix for salt-ssh and avoiding race condition on salt-ssh event processing (bsc#1179831, bsc#1182281)
- Add notify beacon for Debian/Ubuntu systems
- Fix zmq bug that causes salt-call to freeze (bsc#1181368)");

  script_tag(name:"affected", value:"'Salt' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-standalone-formulas-configuration", rpm:"salt-standalone-formulas-configuration~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-transactional-update", rpm:"salt-transactional-update~3002.2~8.41.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~3002.2~8.41.8.1", rls:"SLES15.0"))) {
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
