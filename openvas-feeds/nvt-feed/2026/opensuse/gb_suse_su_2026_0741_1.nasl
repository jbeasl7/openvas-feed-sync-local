# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0741.1");
  script_cve_id("CVE-2024-2312");
  script_tag(name:"creation_date", value:"2026-03-04 04:34:20 +0000 (Wed, 04 Mar 2026)");
  script_version("2026-03-05T05:55:06+0000");
  script_tag(name:"last_modification", value:"2026-03-05 05:55:06 +0000 (Thu, 05 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0741-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0741-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260741-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247432");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024522.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shim' package(s) announced via the SUSE-SU-2026:0741-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for shim fixes the following issues:

shim is updated to version 16.1:

- shim_start_image(): fix guid/handle pairing when uninstalling protocols
- Fix uncompressed ipv6 netboot
- fix test segfaults caused by uninitialized memory
- SbatLevel_Variable.txt: minor typo fix.
- Realloc() needs to allocate one more byte for sprintf()
- IPv6: Add more check to avoid multiple double colon and illegal char
- Loader proto v2
- loader-protocol: add workaround for EDK2 2025.02 page fault on FreePages
- Generate Authenticode for the entire PE file
- README: mention new loader protocol and interaction with UKIs
- shim: change automatically enable MOK_POLICY_REQUIRE_NX
- Save var info
- add SbatLevel entry 2025051000 for PSA-2025-00012-1
- Coverity fixes 20250804
- fix http boot
- Fix double free and leak in the loader protocol


shim is updated to version 16.0:


- Validate that a supplied vendor cert is not in PEM format
- sbat: Add grub.peimage,2 to latest (CVE-2024-2312)
- sbat: Also bump latest for grub,4 (and to todays date)
- undo change that limits certificate files to a single file
- shim: don't set second_stage to the empty string
- Fix SBAT.md for today's consensus about numbers
- Update Code of Conduct contact address
- make-certs: Handle missing OpenSSL installation
- Update MokVars.txt
- export DEFINES for sub makefile
- Drop unused EFI_IMAGE_SECURITY_DATABASE_GUID definition
- Null-terminate 'arguments' in fallback
- Fix 'Verifiying' typo in error message
- Update Fedora CI targets
- Force gcc to produce DWARF4 so that gdb can use it
- Minor housekeeping 2024121700
- Discard load-options that start with WINDOWS
- Fix the issue that the gBS->LoadImage pointer was empty.
- shim: Allow data after the end of device path node in load options
- Handle network file not found like disks
- Update gnu-efi submodule for EFI_HTTP_ERROR
- Increase EFI file alignment
- avoid EFIv2 runtime services on Apple x86 machines
- Improve shortcut performance when comparing two boolean expressions
- Provide better error message when MokManager is not found
- tpm: Boot with a warning if the event log is full
- MokManager: remove redundant logical constraints
- Test import_mok_state() when MokListRT would be bigger than available size
- test-mok-mirror: minor bug fix
- Fix file system browser hang when enrolling MOK from disk
- Ignore a minor clang-tidy nit
- Allow fallback to default loader when encountering errors on network boot
- test.mk: don't use a temporary random.bin
- pe: Enhance debug report for update_mem_attrs
- Multiple certificate handling improvements
- Generate SbatLevel Metadata from SbatLevel_Variable.txt
- Apply EKU check with compile option
- Add configuration option to boot an alternative 2nd stage
- Loader protocol (with Device Path resolution support)
- netboot cleanup for additional files
- Document how revocations can be delivered
- post-process-pe: add tests ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'shim' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"shim", rpm:"shim~16.1~150300.4.31.3", rls:"openSUSELeap15.6"))) {
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
