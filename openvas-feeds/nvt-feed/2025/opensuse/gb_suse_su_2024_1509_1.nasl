# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.1509.1");
  script_cve_id("CVE-2016-8614", "CVE-2016-8628", "CVE-2016-8647", "CVE-2016-9587", "CVE-2017-7550", "CVE-2018-10874", "CVE-2020-10744", "CVE-2020-14330", "CVE-2020-14332", "CVE-2020-14365", "CVE-2020-1753", "CVE-2023-5764", "CVE-2023-6152", "CVE-2024-0690", "CVE-2024-1313");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-06 13:13:23 +0000 (Wed, 06 Jun 2018)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1509-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1509-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241509-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166389");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222155");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035168.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2024:1509-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

POS_Image-Graphical7 was updated to version 0.1.1710765237.46af599:

- Version 0.1.1710765237.46af599

 * Moved image services to dracut-saltboot package
 * Use salt bundle

- Version 0.1.1645440615.7f1328c

 * Removed deprecated kiwi functions

POS_Image-JeOS7 was updated to version 0.1.1710765237.46af599:

- Version 0.1.1710765237.46af599

 * Moved image services to dracut-saltboot package
 * Use salt bundle

- Version 0.1.1645440615.7f1328c

 * Removed deprecated kiwi functions

ansible received the following fixes:

- Security issues fixed:

 * CVE-2023-5764: Address issues where internal templating can cause unsafe
 variables to lose their unsafe designation (bsc#1216854)

 + Breaking changes:
 assert - Nested templating may result in an inability for the conditional
 to be evaluated. See the porting guide for more information.

 * CVE-2024-0690: Address issue where ANSIBLE_NO_LOG was ignored (bsc#1219002)
 * CVE-2020-14365: Ensure that packages are GPG validated (bsc#1175993)
 * CVE-2020-10744: Fixed insecure temporary directory creation (bsc#1171823)
 * CVE-2018-10874: Fixed inventory variables loading from current working directory when running ad-hoc command that
 can lead to code execution (bsc#1099805)

- Bugs fixed:

 * Don't Require python-coverage, it is needed only for testing (bsc#1177948)

dracut-saltboot was updated to version 0.1.1710765237.46af599:

- Version 0.1.1710765237.46af599

 * Load only first available leaseinfo (bsc#1221092)

- Version 0.1.1681904360.84ef141

grafana was updated to version 9.5.18:

- Grafana now requires Go 1.20
- Security issues fixed:

 * CVE-2024-1313: Require same organisation when deleting snapshots (bsc#1222155)
 * CVE-2023-6152: Add email verification when updating user email (bsc#1219912)

- Other non-security related changes:

 * Version 9.5.17:

 + [FEATURE] Alerting: Backport use Alertmanager API v2

 * Version 9.5.16:

 + [BUGFIX] Annotations: Split cleanup into separate queries and
 deletes to avoid deadlocks on MySQL

 * Version 9.5.15:

 + [FEATURE] Alerting: Attempt to retry retryable errors

 * Version 9.5.14:

 + [BUGFIX] Alerting: Fix state manager to not keep
 datasource_uid and ref_id labels in state after Error
 + [BUGFIX] Transformations: Config overrides being lost when
 config from query transform is applied
 + [BUGFIX] LDAP: Fix enable users on successfull login

 * Version 9.5.13:

 + [BUGFIX] BrowseDashboards: Only remember the most recent
 expanded folder
 + [BUGFIX] Licensing: Pass func to update env variables when
 starting plugin

 * Version 9.5.12:

 + [FEATURE] Azure: Add support for Workload Identity
 authentication

 * Version 9.5.9:

 + [FEATURE] SSE: Fix DSNode to not panic when response has empty
 response
 + [FEATURE] Prometheus: Handle the response with different field
 key order
 + [BUGFIX] LDAP: Fix user disabling

mgr-daemon was updated to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"POS_Image-Graphical7", rpm:"POS_Image-Graphical7~0.1.1710765237.46af599~150000.1.21.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"POS_Image-JeOS7", rpm:"POS_Image-JeOS7~0.1.1710765237.46af599~150000.1.21.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.9.27~150000.1.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible-doc", rpm:"ansible-doc~2.9.27~150000.1.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible-test", rpm:"ansible-test~2.9.27~150000.1.17.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-saltboot", rpm:"dracut-saltboot~0.1.1710765237.46af599~150000.1.53.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-promu", rpm:"golang-github-prometheus-promu~0.14.0~150000.3.18.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.3.27~150000.3.116.2", rls:"openSUSELeap15.5"))) {
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
