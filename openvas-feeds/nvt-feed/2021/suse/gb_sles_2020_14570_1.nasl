# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.14570.1");
  script_cve_id("CVE-2020-16846", "CVE-2020-17490", "CVE-2020-25592");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:47 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 15:14:38 +0000 (Mon, 16 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:14570-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:14570-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-202014570-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2020:14570-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

cobbler:

Fix parsing cobbler dictionary options with values containing '=', e.g.
 kernel params containing '=' (bsc#1176978)

golang-github-wrouesnel-postgres_exporter:

Enable package building for ppc64le

mgr-cfg:

Update package version to 4.2.0

mgr-custom-info:

Update package version to 4.2.0

mgr-daemon:

Added quotes around %{_vendor} token for the if statements in spec file.

Fix removal of mgr-deamon with selinux enabled (bsc#1177928)

Updating translations from weblate

Remove duplicate languages and update translation strings

mgr-osad:

Python fixes

Removal of RHEL5

Move uyuni-base-common dependency from mgr-osad to mgr-osa-dispatcher
 (bsc#1174405)

mgr-push:

Defined __python for python2.

Excluded RHEL8 for Python 2 build.

mgr-virtualization:

Update package version to 4.2.0

rhnlib:

Update package version to 4.2.0

salt:

Properly validate eauth credentials and tokens on SSH calls made by Salt
 API (bsc#1178319, bsc#1178362, bsc#1178361) (CVE-2020-25592,
 CVE-2020-17490, CVE-2020-16846)

spacecmd:

Update translations

Fix: make spacecmd build on Debian

Python3 fixes for errata in spacecmd (bsc#1169664)

Added support for i18n of user-facing strings

Python3 fix for sorted usage (bsc#1167907)

Fix softwarechannel_listlatestpackages throwing error on empty channels
 (bsc#1175889)

Add Service Pack migration operations (bsc#1173557)

Fix softwarechannel update for vendor channels (bsc#1172709)

Fix escaping of package names (bsc#1171281)

spacewalk-client-tools:

Updated RHEL Python requirements.

Added quotes around %{_vendor}.

Remove RH references in Python/Ruby localization and use the product
 name instead

Updating translations from weblate

Remove duplicated languages and update translation strings

spacewalk-koan:

Adjust ownership of some tests files to fix them

Fix for spacewalk-koan test

spacewalk-oscap:

Update package version to 4.2.0

spacewalk-remote-utils:

Update package version to 4.2.0

supportutils-plugin-susemanager-client:

Remove checks for obsolete packages

Gather new configfiles

Add more important informations

suseRegisterInfo:

Adapted for RHEL build.

Enhance RedHat product detection for CentOS and OracleLinux (bsc#1173584)

uyuni-base:

Added RHEL8 compatibility.

uyuni-common-libs:

Cleaning up unused Python 2 build leftovers.

Disabled debug package build.

Fix issues importing RPM packages with long RPM headers (bsc#1174965)

zypp-plugin-spacewalk:

Support 'allow vendor change' for dist upgrades");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~0.18.1~8.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-wrouesnel-postgres_exporter", rpm:"golang-github-wrouesnel-postgres_exporter~0.4.7~8.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kiwi-desc-saltboot", rpm:"kiwi-desc-saltboot~0.1.1585064259.12b97ef~8.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"koan", rpm:"koan~2.2.2~0.72.9.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyaml-0-2", rpm:"libyaml-0-2~0.1.3~0.10.28.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq3", rpm:"libzmq3~4.0.4~6.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg", rpm:"mgr-cfg~4.2.1~8.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-actions", rpm:"mgr-cfg-actions~4.2.1~8.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-client", rpm:"mgr-cfg-client~4.2.1~8.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-management", rpm:"mgr-cfg-management~4.2.1~8.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-custom-info", rpm:"mgr-custom-info~4.2.1~8.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-daemon", rpm:"mgr-daemon~4.2.4~8.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-osad", rpm:"mgr-osad~4.2.2~8.9.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-push", rpm:"mgr-push~4.2.2~8.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-virtualization-host", rpm:"mgr-virtualization-host~4.2.1~8.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-Jinja2", rpm:"python-Jinja2~2.6~2.23.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-MarkupSafe", rpm:"python-MarkupSafe~0.18~0.12.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-backports.ssl_match_hostname", rpm:"python-backports.ssl_match_hostname~3.4.0.2~7.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-certifi", rpm:"python-certifi~2015.9.6.2~7.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-futures", rpm:"python-futures~2.1.3~0.10.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-jabberpy", rpm:"python-jabberpy~0.5~0.17.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-msgpack-python", rpm:"python-msgpack-python~0.4.6~6.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-psutil", rpm:"python-psutil~1.2.1~0.10.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pycrypto", rpm:"python-pycrypto~2.6.1~9.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyinotify", rpm:"python-pyinotify~0.9.6~6.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyzmq", rpm:"python-pyzmq~14.0.0~6.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-requests", rpm:"python-requests~2.0.1~0.18.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-simplejson", rpm:"python-simplejson~2.1.1~1.16.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado", rpm:"python-tornado~4.2.1~9.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-yaml", rpm:"python-yaml~3.09~0.12.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg", rpm:"python2-mgr-cfg~4.2.1~8.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-actions", rpm:"python2-mgr-cfg-actions~4.2.1~8.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-client", rpm:"python2-mgr-cfg-client~4.2.1~8.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-management", rpm:"python2-mgr-cfg-management~4.2.1~8.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osa-common", rpm:"python2-mgr-osa-common~4.2.2~8.9.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osad", rpm:"python2-mgr-osad~4.2.2~8.9.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-push", rpm:"python2-mgr-push~4.2.2~8.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-common", rpm:"python2-mgr-virtualization-common~4.2.1~8.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-host", rpm:"python2-mgr-virtualization-host~4.2.1~8.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-rhnlib", rpm:"python2-rhnlib~4.2.1~15.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-check", rpm:"python2-spacewalk-check~4.2.4~30.18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-setup", rpm:"python2-spacewalk-client-setup~4.2.4~30.18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-tools", rpm:"python2-spacewalk-client-tools~4.2.4~30.18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-koan", rpm:"python2-spacewalk-koan~4.2.3~12.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-oscap", rpm:"python2-spacewalk-oscap~4.2.1~9.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-suseRegisterInfo", rpm:"python2-suseRegisterInfo~4.2.2~9.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-uyuni-common-libs", rpm:"python2-uyuni-common-libs~4.2.2~7.15.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-zypp-plugin-spacewalk", rpm:"python2-zypp-plugin-spacewalk~1.0.8~30.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2016.11.10~46.12.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2016.11.10~46.12.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2016.11.10~46.12.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.2.3~21.12.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-backend-libs", rpm:"spacewalk-backend-libs~4.0.31~31.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-check", rpm:"spacewalk-check~4.2.4~30.18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-setup", rpm:"spacewalk-client-setup~4.2.4~30.18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-tools", rpm:"spacewalk-client-tools~4.2.4~30.18.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-koan", rpm:"spacewalk-koan~4.2.3~12.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-oscap", rpm:"spacewalk-oscap~4.2.1~9.6.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-remote-utils", rpm:"spacewalk-remote-utils~4.2.1~9.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-usix", rpm:"spacewalk-usix~4.0.9~6.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils-plugin-salt", rpm:"supportutils-plugin-salt~1.1.4~9.3.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils-plugin-susemanager-client", rpm:"supportutils-plugin-susemanager-client~4.2.2~12.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"suseRegisterInfo", rpm:"suseRegisterInfo~4.2.2~9.9.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uyuni-base-common", rpm:"uyuni-base-common~4.2.2~7.6.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypp-plugin-spacewalk", rpm:"zypp-plugin-spacewalk~1.0.8~30.9.2", rls:"SLES11.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-node_exporter", rpm:"golang-github-prometheus-node_exporter~0.18.1~8.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-wrouesnel-postgres_exporter", rpm:"golang-github-wrouesnel-postgres_exporter~0.4.7~8.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kiwi-desc-saltboot", rpm:"kiwi-desc-saltboot~0.1.1585064259.12b97ef~8.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"koan", rpm:"koan~2.2.2~0.72.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyaml-0-2", rpm:"libyaml-0-2~0.1.3~0.10.28.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzmq3", rpm:"libzmq3~4.0.4~6.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg", rpm:"mgr-cfg~4.2.1~8.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-actions", rpm:"mgr-cfg-actions~4.2.1~8.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-client", rpm:"mgr-cfg-client~4.2.1~8.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-cfg-management", rpm:"mgr-cfg-management~4.2.1~8.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-custom-info", rpm:"mgr-custom-info~4.2.1~8.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-daemon", rpm:"mgr-daemon~4.2.4~8.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-osad", rpm:"mgr-osad~4.2.2~8.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-push", rpm:"mgr-push~4.2.2~8.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgr-virtualization-host", rpm:"mgr-virtualization-host~4.2.1~8.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-Jinja2", rpm:"python-Jinja2~2.6~2.23.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-MarkupSafe", rpm:"python-MarkupSafe~0.18~0.12.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-backports.ssl_match_hostname", rpm:"python-backports.ssl_match_hostname~3.4.0.2~7.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-certifi", rpm:"python-certifi~2015.9.6.2~7.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-futures", rpm:"python-futures~2.1.3~0.10.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-jabberpy", rpm:"python-jabberpy~0.5~0.17.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-msgpack-python", rpm:"python-msgpack-python~0.4.6~6.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-psutil", rpm:"python-psutil~1.2.1~0.10.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pycrypto", rpm:"python-pycrypto~2.6.1~9.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyinotify", rpm:"python-pyinotify~0.9.6~6.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyzmq", rpm:"python-pyzmq~14.0.0~6.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-requests", rpm:"python-requests~2.0.1~0.18.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-simplejson", rpm:"python-simplejson~2.1.1~1.16.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado", rpm:"python-tornado~4.2.1~9.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-yaml", rpm:"python-yaml~3.09~0.12.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg", rpm:"python2-mgr-cfg~4.2.1~8.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-actions", rpm:"python2-mgr-cfg-actions~4.2.1~8.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-client", rpm:"python2-mgr-cfg-client~4.2.1~8.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-cfg-management", rpm:"python2-mgr-cfg-management~4.2.1~8.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osa-common", rpm:"python2-mgr-osa-common~4.2.2~8.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-osad", rpm:"python2-mgr-osad~4.2.2~8.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-push", rpm:"python2-mgr-push~4.2.2~8.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-common", rpm:"python2-mgr-virtualization-common~4.2.1~8.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mgr-virtualization-host", rpm:"python2-mgr-virtualization-host~4.2.1~8.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-rhnlib", rpm:"python2-rhnlib~4.2.1~15.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-check", rpm:"python2-spacewalk-check~4.2.4~30.18.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-setup", rpm:"python2-spacewalk-client-setup~4.2.4~30.18.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-client-tools", rpm:"python2-spacewalk-client-tools~4.2.4~30.18.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-koan", rpm:"python2-spacewalk-koan~4.2.3~12.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-spacewalk-oscap", rpm:"python2-spacewalk-oscap~4.2.1~9.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-suseRegisterInfo", rpm:"python2-suseRegisterInfo~4.2.2~9.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-uyuni-common-libs", rpm:"python2-uyuni-common-libs~4.2.2~7.15.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-zypp-plugin-spacewalk", rpm:"python2-zypp-plugin-spacewalk~1.0.8~30.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2016.11.10~46.12.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2016.11.10~46.12.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2016.11.10~46.12.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~4.2.3~21.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-backend-libs", rpm:"spacewalk-backend-libs~4.0.31~31.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-check", rpm:"spacewalk-check~4.2.4~30.18.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-setup", rpm:"spacewalk-client-setup~4.2.4~30.18.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-tools", rpm:"spacewalk-client-tools~4.2.4~30.18.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-koan", rpm:"spacewalk-koan~4.2.3~12.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-oscap", rpm:"spacewalk-oscap~4.2.1~9.6.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-remote-utils", rpm:"spacewalk-remote-utils~4.2.1~9.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-usix", rpm:"spacewalk-usix~4.0.9~6.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils-plugin-salt", rpm:"supportutils-plugin-salt~1.1.4~9.3.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils-plugin-susemanager-client", rpm:"supportutils-plugin-susemanager-client~4.2.2~12.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"suseRegisterInfo", rpm:"suseRegisterInfo~4.2.2~9.9.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uyuni-base-common", rpm:"uyuni-base-common~4.2.2~7.6.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypp-plugin-spacewalk", rpm:"zypp-plugin-spacewalk~1.0.8~30.9.2", rls:"SLES11.0SP4"))) {
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
