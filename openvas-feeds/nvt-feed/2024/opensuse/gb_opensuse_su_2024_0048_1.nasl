# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833269");
  script_cve_id("CVE-2023-26437", "CVE-2023-50387", "CVE-2023-50868");
  script_tag(name:"creation_date", value:"2024-03-04 12:55:16 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-20 16:55:30 +0000 (Tue, 20 Feb 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0048-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0048-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KZPNQJJ7XX3KPQTYPFVQXAGEDZZNY73R/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219826");
  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2024-01.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns-recursor' package(s) announced via the openSUSE-SU-2024:0048-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pdns-recursor fixes the following issues:

Update to 4.8.6:

* fixes case when crafted DNSSEC records in a zone can lead to
 a denial of service in Recursor
 [link moved to references]
 (boo#1219823, boo#1219826, CVE-2023-50387, CVE-2023-50868)


Changes in 4.8.5:

* (I)XFR: handle partial read of len prefix.
* YaHTTP: Prevent integer overflow on very large chunks.
* Fix setting of policy tags for packet cache hits.

Changes in 4.8.4:

* Deterred spoofing attempts can lead to authoritative servers
 being marked unavailable (boo#1209897, CVE-2023-26437)");

  script_tag(name:"affected", value:"'pdns-recursor' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"pdns-recursor", rpm:"pdns-recursor~4.8.6~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
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
