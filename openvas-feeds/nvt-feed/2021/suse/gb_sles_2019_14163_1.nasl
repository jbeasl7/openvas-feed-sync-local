# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14163.1");
  script_cve_id("CVE-2019-10136");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:19 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-07 21:59:24 +0000 (Sun, 07 Jul 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14163-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14163-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914163-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148311");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-September/005884.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2019:14163-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

mgr-cfg:

- Ensure bytes type when using hashlib to avoid traceback (bsc#1138822)

mgr-daemon:

- Fix systemd timer configuration on SLE12 (bsc#1142038)

mgr-osad:

- Fix obsolete for old osad packages, to allow installing mgr-osad
 even by using osad at yum/zyppper install (bsc#1139453)
- Ensure bytes type when using hashlib to avoid traceback (bsc#1138822)

mgr-virtualization:

- Fix missing python 3 ugettext (bsc#1138494)
- Fix package dependencies to prevent file conflict (bsc#1143856)

rhnlib:

- Add SNI support for clients
- Fix initialize ssl connection (bsc#1144155)
- Fix bootstrapping SLE11SP4 trad client with SSL enabled (bsc#1148177)

python-gzipstream:

- SPEC cleanup
- add makefile and pylint configuration
- Add Uyuni URL to package
- Bump version to 4.0.0 (bsc#1104034)
- Fix copyright for the package specfile (bsc#1103696)

spacecmd:

- Bugfix: referenced variable before assignment.
- Bugfix: 'dict' object has no attribute 'iteritems' (bsc#1135881)
- Add unit tests for custominfo, snippet, scap, ssm, cryptokey and distribution
- Fix missing runtime dependencies that made spacecmd return old versions of
 packages in some cases, even if newer ones were available (bsc#1148311)


spacewalk-backend:

- Do not overwrite comps and module data with older versions
- Fix issue with 'dists' keyword in url hostname
- Import packages from all collections of a patch not just first one
- Ensure bytes type when using hashlib to avoid traceback
 on XMLRPC call to 'registration.register_osad' (bsc#1138822)
- Do not duplicate 'http://' protocol when using proxies with 'deb'
 repositories (bsc#1138313)
- Fix reposync when dealing with RedHat CDN (bsc#1138358)
- Fix for CVE-2019-10136. An attacker with a valid, but expired,
 authenticated set of headers could move some digits around,
 artificially extending the session validity without modifying
 the checksum. (bsc#1136480)
- Prevent FileNotFoundError: repomd.xml.key traceback (bsc#1137940)
- Add journalctl output to spacewalk-debug tarballs
- Prevent unnecessary triggering of channel-repodata tasks when GPG
 signing is disabled (bsc#1137715)
- Fix spacewalk-repo-sync for Ubuntu repositories in mirror case (bsc#1136029)
- Add support for ULN repositories on new Zypper based reposync.
- Don't skip Deb package tags on package import (bsc#1130040)
- For backend-libs subpackages, exclude files for the server
 (already part of spacewalk-backend) to avoid conflicts (bsc#1148125)
- prevent duplicate key violates on repo-sync with long changelog
 entries (bsc#1144889)

spacewalk-remote-utils:

- Add RHEL8");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg", rpm:"mgr-cfg~4.0.9~5.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-actions", rpm:"mgr-cfg-actions~4.0.9~5.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-client", rpm:"mgr-cfg-client~4.0.9~5.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-management", rpm:"mgr-cfg-management~4.0.9~5.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-daemon", rpm:"mgr-daemon~4.0.7~5.8.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-osad", rpm:"mgr-osad~4.0.9~5.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-virtualization-host", rpm:"mgr-virtualization-host~4.0.8~5.8.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg", rpm:"python2-mgr-cfg~4.0.9~5.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-actions", rpm:"python2-mgr-cfg-actions~4.0.9~5.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-client", rpm:"python2-mgr-cfg-client~4.0.9~5.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-management", rpm:"python2-mgr-cfg-management~4.0.9~5.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osa-common", rpm:"python2-mgr-osa-common~4.0.9~5.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osad", rpm:"python2-mgr-osad~4.0.9~5.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-common", rpm:"python2-mgr-virtualization-common~4.0.8~5.8.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-host", rpm:"python2-mgr-virtualization-host~4.0.8~5.8.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-rhnlib", rpm:"python2-rhnlib~4.0.11~12.16.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.0.14~18.51.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-backend-libs", rpm:"spacewalk-backend-libs~4.0.25~28.42.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-remote-utils", rpm:"spacewalk-remote-utils~4.0.5~6.12.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg", rpm:"mgr-cfg~4.0.9~5.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-actions", rpm:"mgr-cfg-actions~4.0.9~5.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-client", rpm:"mgr-cfg-client~4.0.9~5.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-management", rpm:"mgr-cfg-management~4.0.9~5.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-daemon", rpm:"mgr-daemon~4.0.7~5.8.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-osad", rpm:"mgr-osad~4.0.9~5.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-virtualization-host", rpm:"mgr-virtualization-host~4.0.8~5.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg", rpm:"python2-mgr-cfg~4.0.9~5.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-actions", rpm:"python2-mgr-cfg-actions~4.0.9~5.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-client", rpm:"python2-mgr-cfg-client~4.0.9~5.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-management", rpm:"python2-mgr-cfg-management~4.0.9~5.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osa-common", rpm:"python2-mgr-osa-common~4.0.9~5.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osad", rpm:"python2-mgr-osad~4.0.9~5.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-common", rpm:"python2-mgr-virtualization-common~4.0.8~5.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-host", rpm:"python2-mgr-virtualization-host~4.0.8~5.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-rhnlib", rpm:"python2-rhnlib~4.0.11~12.16.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.0.14~18.51.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-backend-libs", rpm:"spacewalk-backend-libs~4.0.25~28.42.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-remote-utils", rpm:"spacewalk-remote-utils~4.0.5~6.12.2", rls:"SLES11.0SP4"))) {
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
