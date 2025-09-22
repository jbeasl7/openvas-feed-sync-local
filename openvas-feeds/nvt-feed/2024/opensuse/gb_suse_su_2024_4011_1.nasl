# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856728");
  script_cve_id("CVE-2023-3978");
  script_tag(name:"creation_date", value:"2024-11-21 05:00:33 +0000 (Thu, 21 Nov 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-07 18:24:33 +0000 (Mon, 07 Aug 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:4011-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4011-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244011-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231206");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019833.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2024:4011-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

golang-github-lusitaniae-apache_exporter:

- Security issues fixed:

 * CVE-2023-3978: Fixed security bug in x/net dependency (bsc#1213933)

- Other changes and issues fixed:

 * Delete unpackaged debug files for RHEL
 * Do not include source files in the package for RHEL 9
 * Require Go 1.20 when building for RedHat derivatives
 * Drop EnvironmentFile from the service definition
 * Explicitly unset $ARGS environment variable. Setting environment
 variables should be done in drop-in systemd configuration files.
 * Drop go_nostrip macro. It is not needed with current binutils and
 Go.
 * Migrate from `disabled` to `manual` source service type
 * Drop BuildRequires: golang-packaging
 * Upgrade to version 1.0.8 (bsc#1227341)
 + Update prometheus/client_golang to version 1.19.1
 + Update x/net to version 0.23.0
 * Upgrade to version 1.0.7
 + Update protobuf to version 1.33.0
 + Update prometheus/client_golang to version 1.19.0
 + Update prometheus/common to version 0.46.0
 + Standardize landing page
 * Upgrade to version 1.0.6
 + Update prometheus/exporter-toolkit to version 0.11.0
 + Update prometheus/client_golang to version 1.18.0
 + Add User-Agent header
 * Upgrade to version 1.0.4
 + Update x/crypto to version 0.17.0
 + Update alecthomas/kingpin/v2 to version 2.4.0
 + Update prometheus/common to version 0.45.0
 * Upgrade to version 1.0.3
 + Update prometheus/client_golang to version 1.17.0
 + Update x/net 0.17.0
 * Upgrade to version 1.0.1
 + Update prometheus/exporter-toolkit to version 0.10.0
 + Update prometheus/common to version 0.44.0
 + Update prometheus/client_golang to version 1.16.0

golang-github-prometheus-promu:

- Require Go >= 1.21 for building
- Packaging improvements:
 * Drop export CGO_ENABLED='0'. Use the default unless there is a
 defined requirement or benefit (bsc#1230623).
- Update to version 0.16.0:
 * Do not discover user/host for reproducible builds
 * Fix example/prometheus build error
- Update to version 0.15.0:
 * Add linux/riscv64 to default platforms
 * Use yaml.Unmarshalstrict to validate configuration files

spacecmd:

- Version 5.0.10-0
 * Speed up softwarechannel_removepackages (bsc#1227606)
 * Fix error in 'kickstart_delete' when using wildcards
 (bsc#1227578)
 * Spacecmd bootstrap now works with specified port (bsc#1229437)
 * Fix sls backup creation as directory with spacecmd (bsc#1230745)

uyuni-common-libs:

- Version 5.0.5-0
 * Enforce directory permissions at repo-sync when creating
 directories (bsc#1229260)

uyuni-tools:

- version 0.1.23-0
 * Ensure namespace is defined in all kubernetes commands
 * Use SCC credentials to authenticate against registry.suse.com
 for kubernetes (bsc#1231157)
 * Fix namespace usage on mgrctl cp command
- version 0.1.22-0
 * Set projectId also for test packages/images
 * mgradm migration should not pull Confidential Computing and Hub
 image is replicas == 0 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-lusitaniae-apache_exporter", rpm:"golang-github-lusitaniae-apache_exporter~1.0.8~150000.1.23.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-promu", rpm:"golang-github-prometheus-promu~0.16.0~150000.3.21.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~5.0.10~150000.3.127.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wire", rpm:"wire~0.6.0~150000.1.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-lusitaniae-apache_exporter", rpm:"golang-github-lusitaniae-apache_exporter~1.0.8~150000.1.23.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-promu", rpm:"golang-github-prometheus-promu~0.16.0~150000.3.21.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~5.0.10~150000.3.127.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wire", rpm:"wire~0.6.0~150000.1.17.4", rls:"openSUSELeap15.6"))) {
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
