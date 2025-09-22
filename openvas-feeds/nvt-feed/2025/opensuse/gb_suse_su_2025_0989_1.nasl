# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0989.1");
  script_cve_id("CVE-2024-57256", "CVE-2024-57258");
  script_tag(name:"creation_date", value:"2025-03-26 07:47:44 +0000 (Wed, 26 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0989-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0989-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250989-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237287");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020580.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'u-boot' package(s) announced via the SUSE-SU-2025:0989-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for u-boot fixes the following issues:

- CVE-2024-57256: integer overflow in U-Boot's ext4 symlink resolution function (bsc#1237284).
- CVE-2024-57258: multiple integer overflows in U-Boot's memory allocator (bsc#1237287).");

  script_tag(name:"affected", value:"'u-boot' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"u-boot-avnetultra96rev1", rpm:"u-boot-avnetultra96rev1~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-avnetultra96rev1-doc", rpm:"u-boot-avnetultra96rev1-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-bananapim64", rpm:"u-boot-bananapim64~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-bananapim64-doc", rpm:"u-boot-bananapim64-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-dragonboard410c", rpm:"u-boot-dragonboard410c~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-dragonboard410c-doc", rpm:"u-boot-dragonboard410c-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-dragonboard820c", rpm:"u-boot-dragonboard820c~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-dragonboard820c-doc", rpm:"u-boot-dragonboard820c-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-evb-rk3399", rpm:"u-boot-evb-rk3399~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-evb-rk3399-doc", rpm:"u-boot-evb-rk3399-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-firefly-rk3399", rpm:"u-boot-firefly-rk3399~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-firefly-rk3399-doc", rpm:"u-boot-firefly-rk3399-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-geekbox", rpm:"u-boot-geekbox~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-geekbox-doc", rpm:"u-boot-geekbox-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-hikey", rpm:"u-boot-hikey~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-hikey-doc", rpm:"u-boot-hikey-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-khadas-vim", rpm:"u-boot-khadas-vim~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-khadas-vim-doc", rpm:"u-boot-khadas-vim-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-khadas-vim2", rpm:"u-boot-khadas-vim2~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-khadas-vim2-doc", rpm:"u-boot-khadas-vim2-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-libretech-ac", rpm:"u-boot-libretech-ac~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-libretech-ac-doc", rpm:"u-boot-libretech-ac-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-libretech-cc", rpm:"u-boot-libretech-cc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-libretech-cc-doc", rpm:"u-boot-libretech-cc-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-ls1012afrdmqspi", rpm:"u-boot-ls1012afrdmqspi~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-ls1012afrdmqspi-doc", rpm:"u-boot-ls1012afrdmqspi-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-mvebudb-88f3720", rpm:"u-boot-mvebudb-88f3720~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-mvebudb-88f3720-doc", rpm:"u-boot-mvebudb-88f3720-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-mvebudbarmada8k", rpm:"u-boot-mvebudbarmada8k~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-mvebudbarmada8k-doc", rpm:"u-boot-mvebudbarmada8k-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-mvebuespressobin-88f3720", rpm:"u-boot-mvebuespressobin-88f3720~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-mvebuespressobin-88f3720-doc", rpm:"u-boot-mvebuespressobin-88f3720-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-mvebumcbin-88f8040", rpm:"u-boot-mvebumcbin-88f8040~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-mvebumcbin-88f8040-doc", rpm:"u-boot-mvebumcbin-88f8040-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-nanopia64", rpm:"u-boot-nanopia64~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-nanopia64-doc", rpm:"u-boot-nanopia64-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-odroid-c2", rpm:"u-boot-odroid-c2~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-odroid-c2-doc", rpm:"u-boot-odroid-c2-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-odroid-c4", rpm:"u-boot-odroid-c4~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-odroid-c4-doc", rpm:"u-boot-odroid-c4-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-odroid-n2", rpm:"u-boot-odroid-n2~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-odroid-n2-doc", rpm:"u-boot-odroid-n2-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-orangepipc2", rpm:"u-boot-orangepipc2~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-orangepipc2-doc", rpm:"u-boot-orangepipc2-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-p2371-2180", rpm:"u-boot-p2371-2180~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-p2371-2180-doc", rpm:"u-boot-p2371-2180-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-p2771-0000-500", rpm:"u-boot-p2771-0000-500~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-p2771-0000-500-doc", rpm:"u-boot-p2771-0000-500-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-p3450-0000", rpm:"u-boot-p3450-0000~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-p3450-0000-doc", rpm:"u-boot-p3450-0000-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-pine64plus", rpm:"u-boot-pine64plus~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-pine64plus-doc", rpm:"u-boot-pine64plus-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-pinebook", rpm:"u-boot-pinebook~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-pinebook-doc", rpm:"u-boot-pinebook-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-pinebook-pro-rk3399", rpm:"u-boot-pinebook-pro-rk3399~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-pinebook-pro-rk3399-doc", rpm:"u-boot-pinebook-pro-rk3399-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-pineh64", rpm:"u-boot-pineh64~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-pineh64-doc", rpm:"u-boot-pineh64-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-pinephone", rpm:"u-boot-pinephone~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-pinephone-doc", rpm:"u-boot-pinephone-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-poplar", rpm:"u-boot-poplar~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-poplar-doc", rpm:"u-boot-poplar-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rock-pi-4-rk3399", rpm:"u-boot-rock-pi-4-rk3399~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rock-pi-4-rk3399-doc", rpm:"u-boot-rock-pi-4-rk3399-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rock-pi-n10-rk3399pro", rpm:"u-boot-rock-pi-n10-rk3399pro~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rock-pi-n10-rk3399pro-doc", rpm:"u-boot-rock-pi-n10-rk3399pro-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rock64-rk3328", rpm:"u-boot-rock64-rk3328~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rock64-rk3328-doc", rpm:"u-boot-rock64-rk3328-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rock960-rk3399", rpm:"u-boot-rock960-rk3399~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rock960-rk3399-doc", rpm:"u-boot-rock960-rk3399-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rockpro64-rk3399", rpm:"u-boot-rockpro64-rk3399~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rockpro64-rk3399-doc", rpm:"u-boot-rockpro64-rk3399-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rpi3", rpm:"u-boot-rpi3~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rpi3-doc", rpm:"u-boot-rpi3-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rpi4", rpm:"u-boot-rpi4~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rpi4-doc", rpm:"u-boot-rpi4-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rpiarm64", rpm:"u-boot-rpiarm64~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rpiarm64-doc", rpm:"u-boot-rpiarm64-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-tools", rpm:"u-boot-tools~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-xilinxzynqmpvirt", rpm:"u-boot-xilinxzynqmpvirt~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-xilinxzynqmpvirt-doc", rpm:"u-boot-xilinxzynqmpvirt-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-xilinxzynqmpzcu102rev10", rpm:"u-boot-xilinxzynqmpzcu102rev10~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-xilinxzynqmpzcu102rev10-doc", rpm:"u-boot-xilinxzynqmpzcu102rev10-doc~2021.10~150600.11.3.1", rls:"openSUSELeap15.6"))) {
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
