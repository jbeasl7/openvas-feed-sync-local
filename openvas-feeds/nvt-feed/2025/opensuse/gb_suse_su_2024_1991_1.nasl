# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.1991.1");
  script_cve_id("CVE-2022-30698", "CVE-2022-30699", "CVE-2022-3204", "CVE-2023-50387", "CVE-2023-50868");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-20 16:55:30 +0000 (Tue, 20 Feb 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1991-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1991-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241991-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219826");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-June/018692.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unbound' package(s) announced via the SUSE-SU-2024:1991-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* CVE-2023-50387: DNSSEC verification complexity can be
 exploited to exhaust CPU resources and stall DNS resolvers. [bsc#1219823]
* CVE-2023-50868: NSEC3 closest encloser proof can exhaust CPU.
 [bsc#1219826]
* CVE-2022-30698: Novel 'ghost domain names' attack by
 introducing subdomain delegations. [bsc#1202033]
* CVE-2022-30699: Novel 'ghost domain names' attack by
 updating almost expired delegation information. [bsc#1202031]
* CVE-2022-3204: NRDelegation attack leads to uncontrolled
 resource consumption (Non-Responsive Delegation Attack). [bsc#1203643]

Packaging Changes:

* Use prefixes instead of sudo in unbound.service
* Remove no longer necessary BuildRequires: libfstrm-devel and
 libprotobuf-c-devel");

  script_tag(name:"affected", value:"'unbound' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libunbound8", rpm:"libunbound8~1.20.0~150100.10.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound", rpm:"unbound~1.20.0~150100.10.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-anchor", rpm:"unbound-anchor~1.20.0~150100.10.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-devel", rpm:"unbound-devel~1.20.0~150100.10.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-munin", rpm:"unbound-munin~1.20.0~150100.10.13.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-python", rpm:"unbound-python~1.20.0~150100.10.13.1", rls:"openSUSELeap15.5"))) {
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
