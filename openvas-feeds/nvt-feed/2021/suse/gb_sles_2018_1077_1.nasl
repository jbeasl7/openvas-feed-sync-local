# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1077.1");
  script_cve_id("CVE-2017-18030", "CVE-2017-5715", "CVE-2018-5683", "CVE-2018-7550");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:45 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-22 16:50:31 +0000 (Thu, 22 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1077-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1077-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181077-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083291");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-April/003961.html");
  script_xref(name:"URL", value:"https://www.qemu.org/2018/02/14/qemu-2-11-1-and-spectre-update/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2018:1077-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kvm fixes the following issues:

- This update has the next round of Spectre v2 related patches,
 which now integrates with corresponding changes in libvirt. A
 January 2018 release of qemu initially addressed the Spectre v2
 vulnerability for KVM guests by exposing the spec-ctrl feature
 for all x86 vcpu types, which was the quick and dirty approach,
 but not the proper solution. We remove that initial patch and now
 rely on patches from upstream. This update defines spec_ctrl and
 ibpb cpu feature flags as well as new cpu models which are clones
 of existing models with either -IBRS or -IBPB added to the end of
 the model name. These new vcpu models explicitly include the new
 feature(s), whereas the feature flags can be added to the cpu
 parameter as with other features. In short, for continued Spectre
 v2 protection, ensure that either the appropriate cpu feature
 flag is added to the QEMU command-line, or one of the new cpu
 models is used. Although migration from older versions is
 supported, the new cpu features won't be properly exposed to the
 guest until it is restarted with the cpu features explicitly
 added. A reboot is insufficient.
- A warning patch is added which attempts to detect a migration
 from a qemu version which had the quick and dirty fix (it only
 detects certain cases, but hopefully is helpful.)
 For additional information on Spectre v2 as it relates to QEMU,
 see: [link moved to references]
 (CVE-2017-5715 bsc#1068032)
- A patch is added to continue to detect Spectre v2 mitigation
 features (as shown by cpuid), and if found provide that feature
 to guests, even if running on older KVM (kernel) versions which
 do not yet expose that feature to QEMU. (bsc#1082276)
 These two patches will be removed when we can reasonably assume
 everyone is running with the appropriate updates.

- Security fixes for the following CVE issues:
 (bsc#1076114 CVE-2018-5683)
 (bsc#1083291 CVE-2018-7550)
- This patch is already included, add here for CVE track
 (bsc#1076179 CVE-2017-18030)

- Toolchain changes have cause the built size of pxe-virtio.rom to
 exceed 64K. Tweak rarely used strings in code to reduce size of
 the binary so it fits again.

- Eliminate bogus use of CPUID_7_0_EDX_PRED_CMD which we've
 carried since the initial Spectre v2 patch was added. EDX bit
 27 of CPUID Leaf 07H, Sub-leaf 0 provides status on STIBP, and
 not the PRED_CMD MSR. Exposing the STIBP CPUID feature bit to the
 guest is wrong in general, since the VM doesn't directly control
 the scheduling of physical hyperthreads. This is left strictly to
 the L0 hypervisor.");

  script_tag(name:"affected", value:"'kvm' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~60.9.1", rls:"SLES11.0SP4"))) {
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
