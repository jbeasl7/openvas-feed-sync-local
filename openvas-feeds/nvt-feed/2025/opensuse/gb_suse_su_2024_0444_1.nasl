# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0444.1");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0444-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0444-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240444-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219189");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017898.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'suse-build-key' package(s) announced via the SUSE-SU-2024:0444-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for suse-build-key fixes the following issues:

This update runs a import-suse-build-key script.

The previous libzypp-post-script based installation is replaced with a systemd timer and service (bsc#1217215 bsc#1216410 jsc#PED-2777).
 - suse-build-key-import.service
 - suse-build-key-import.timer

It imports the future SUSE Linux Enterprise 15 4096 bit RSA key primary and reserve keys.
After successful import the timer is disabled.

To manually import them you can also run:

# rpm --import /usr/lib/rpm/gnupg/keys/gpg-pubkey-3fa1d6ce-63c9481c.asc
# rpm --import /usr/lib/rpm/gnupg/keys/gpg-pubkey-d588dc46-63c939db.asc

Bugfix added since last update:

- run rpm commands in import script only when libzypp is not
 active. bsc#1219189 bsc#1219123");

  script_tag(name:"affected", value:"'suse-build-key' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"suse-build-key", rpm:"suse-build-key~12.0~150000.8.40.1", rls:"openSUSELeap15.5"))) {
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
