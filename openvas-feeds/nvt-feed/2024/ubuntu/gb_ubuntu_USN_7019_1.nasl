# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7019.1");
  script_cve_id("CVE-2022-38096", "CVE-2022-48772", "CVE-2022-48808", "CVE-2023-52488", "CVE-2023-52585", "CVE-2023-52629", "CVE-2023-52699", "CVE-2023-52752", "CVE-2023-52760", "CVE-2023-52880", "CVE-2023-52882", "CVE-2023-52884", "CVE-2023-52887", "CVE-2024-23307", "CVE-2024-23848", "CVE-2024-24857", "CVE-2024-24858", "CVE-2024-24859", "CVE-2024-24861", "CVE-2024-25739", "CVE-2024-25741", "CVE-2024-25742", "CVE-2024-26629", "CVE-2024-26642", "CVE-2024-26654", "CVE-2024-26680", "CVE-2024-26687", "CVE-2024-26810", "CVE-2024-26811", "CVE-2024-26812", "CVE-2024-26813", "CVE-2024-26814", "CVE-2024-26817", "CVE-2024-26828", "CVE-2024-26830", "CVE-2024-26886", "CVE-2024-26900", "CVE-2024-26921", "CVE-2024-26922", "CVE-2024-26923", "CVE-2024-26925", "CVE-2024-26926", "CVE-2024-26929", "CVE-2024-26931", "CVE-2024-26934", "CVE-2024-26935", "CVE-2024-26936", "CVE-2024-26937", "CVE-2024-26950", "CVE-2024-26951", "CVE-2024-26952", "CVE-2024-26955", "CVE-2024-26956", "CVE-2024-26957", "CVE-2024-26958", "CVE-2024-26960", "CVE-2024-26961", "CVE-2024-26964", "CVE-2024-26965", "CVE-2024-26966", "CVE-2024-26969", "CVE-2024-26970", "CVE-2024-26973", "CVE-2024-26974", "CVE-2024-26976", "CVE-2024-26977", "CVE-2024-26980", "CVE-2024-26981", "CVE-2024-26984", "CVE-2024-26988", "CVE-2024-26989", "CVE-2024-26993", "CVE-2024-26994", "CVE-2024-26996", "CVE-2024-26999", "CVE-2024-27000", "CVE-2024-27001", "CVE-2024-27004", "CVE-2024-27008", "CVE-2024-27009", "CVE-2024-27013", "CVE-2024-27015", "CVE-2024-27016", "CVE-2024-27017", "CVE-2024-27018", "CVE-2024-27019", "CVE-2024-27020", "CVE-2024-27059", "CVE-2024-27393", "CVE-2024-27395", "CVE-2024-27396", "CVE-2024-27398", "CVE-2024-27399", "CVE-2024-27401", "CVE-2024-27437", "CVE-2024-31076", "CVE-2024-33621", "CVE-2024-33847", "CVE-2024-34027", "CVE-2024-34777", "CVE-2024-35247", "CVE-2024-35785", "CVE-2024-35789", "CVE-2024-35791", "CVE-2024-35796", "CVE-2024-35804", "CVE-2024-35805", "CVE-2024-35806", "CVE-2024-35807", "CVE-2024-35809", "CVE-2024-35813", "CVE-2024-35815", "CVE-2024-35817", "CVE-2024-35819", "CVE-2024-35821", "CVE-2024-35822", "CVE-2024-35823", "CVE-2024-35825", "CVE-2024-35847", "CVE-2024-35848", "CVE-2024-35849", "CVE-2024-35851", "CVE-2024-35852", "CVE-2024-35853", "CVE-2024-35854", "CVE-2024-35855", "CVE-2024-35857", "CVE-2024-35871", "CVE-2024-35872", "CVE-2024-35877", "CVE-2024-35879", "CVE-2024-35884", "CVE-2024-35885", "CVE-2024-35886", "CVE-2024-35888", "CVE-2024-35890", "CVE-2024-35893", "CVE-2024-35895", "CVE-2024-35896", "CVE-2024-35897", "CVE-2024-35898", "CVE-2024-35899", "CVE-2024-35900", "CVE-2024-35902", "CVE-2024-35905", "CVE-2024-35907", "CVE-2024-35910", "CVE-2024-35912", "CVE-2024-35915", "CVE-2024-35922", "CVE-2024-35925", "CVE-2024-35927", "CVE-2024-35930", "CVE-2024-35933", "CVE-2024-35934", "CVE-2024-35935", "CVE-2024-35936", "CVE-2024-35938", "CVE-2024-35940", "CVE-2024-35944", "CVE-2024-35947", "CVE-2024-35950", "CVE-2024-35955", "CVE-2024-35958", "CVE-2024-35960", "CVE-2024-35969", "CVE-2024-35970", "CVE-2024-35973", "CVE-2024-35976", "CVE-2024-35978", "CVE-2024-35982", "CVE-2024-35984", "CVE-2024-35988", "CVE-2024-35989", "CVE-2024-35990", "CVE-2024-35997", "CVE-2024-36004", "CVE-2024-36005", "CVE-2024-36006", "CVE-2024-36007", "CVE-2024-36008", "CVE-2024-36014", "CVE-2024-36015", "CVE-2024-36016", "CVE-2024-36017", "CVE-2024-36020", "CVE-2024-36025", "CVE-2024-36029", "CVE-2024-36031", "CVE-2024-36032", "CVE-2024-36270", "CVE-2024-36286", "CVE-2024-36489", "CVE-2024-36880", "CVE-2024-36883", "CVE-2024-36886", "CVE-2024-36889", "CVE-2024-36894", "CVE-2024-36901", "CVE-2024-36902", "CVE-2024-36904", "CVE-2024-36905", "CVE-2024-36906", "CVE-2024-36916", "CVE-2024-36919", "CVE-2024-36928", "CVE-2024-36929", "CVE-2024-36931", "CVE-2024-36933", "CVE-2024-36934", "CVE-2024-36937", "CVE-2024-36938", "CVE-2024-36939", "CVE-2024-36940", "CVE-2024-36941", "CVE-2024-36946", "CVE-2024-36947", "CVE-2024-36950", "CVE-2024-36952", "CVE-2024-36953", "CVE-2024-36954", "CVE-2024-36955", "CVE-2024-36957", "CVE-2024-36959", "CVE-2024-36960", "CVE-2024-36964", "CVE-2024-36965", "CVE-2024-36967", "CVE-2024-36969", "CVE-2024-36971", "CVE-2024-36972", "CVE-2024-36974", "CVE-2024-36975", "CVE-2024-36978", "CVE-2024-37078", "CVE-2024-37356", "CVE-2024-38546", "CVE-2024-38547", "CVE-2024-38548", "CVE-2024-38549", "CVE-2024-38550", "CVE-2024-38552", "CVE-2024-38555", "CVE-2024-38558", "CVE-2024-38559", "CVE-2024-38560", "CVE-2024-38565", "CVE-2024-38567", "CVE-2024-38571", "CVE-2024-38573", "CVE-2024-38578", "CVE-2024-38579", "CVE-2024-38580", "CVE-2024-38582", "CVE-2024-38583", "CVE-2024-38586", "CVE-2024-38588", "CVE-2024-38589", "CVE-2024-38590", "CVE-2024-38591", "CVE-2024-38596", "CVE-2024-38597", "CVE-2024-38598", "CVE-2024-38599", "CVE-2024-38600", "CVE-2024-38601", "CVE-2024-38605", "CVE-2024-38607", "CVE-2024-38610", "CVE-2024-38612", "CVE-2024-38613", "CVE-2024-38615", "CVE-2024-38618", "CVE-2024-38619", "CVE-2024-38621", "CVE-2024-38623", "CVE-2024-38624", "CVE-2024-38627", "CVE-2024-38633", "CVE-2024-38634", "CVE-2024-38635", "CVE-2024-38637", "CVE-2024-38659", "CVE-2024-38661", "CVE-2024-38780", "CVE-2024-39276", "CVE-2024-39277", "CVE-2024-39292", "CVE-2024-39301", "CVE-2024-39466", "CVE-2024-39467", "CVE-2024-39468", "CVE-2024-39469", "CVE-2024-39471", "CVE-2024-39475", "CVE-2024-39480", "CVE-2024-39482", "CVE-2024-39484", "CVE-2024-39487", "CVE-2024-39488", "CVE-2024-39489", "CVE-2024-39490", "CVE-2024-39495", "CVE-2024-39499", "CVE-2024-39500", "CVE-2024-39501", "CVE-2024-39502", "CVE-2024-39503", "CVE-2024-39505", "CVE-2024-39506", "CVE-2024-39507", "CVE-2024-39509", "CVE-2024-40901", "CVE-2024-40902", "CVE-2024-40904", "CVE-2024-40905", "CVE-2024-40908", "CVE-2024-40911", "CVE-2024-40912", "CVE-2024-40914", "CVE-2024-40916", "CVE-2024-40927", "CVE-2024-40929", "CVE-2024-40931", "CVE-2024-40932", "CVE-2024-40934", "CVE-2024-40937", "CVE-2024-40941", "CVE-2024-40942", "CVE-2024-40943", "CVE-2024-40945", "CVE-2024-40954", "CVE-2024-40956", "CVE-2024-40957", "CVE-2024-40958", "CVE-2024-40959", "CVE-2024-40960", "CVE-2024-40961", "CVE-2024-40963", "CVE-2024-40967", "CVE-2024-40968", "CVE-2024-40970", "CVE-2024-40971", "CVE-2024-40974", "CVE-2024-40976", "CVE-2024-40978", "CVE-2024-40980", "CVE-2024-40981", "CVE-2024-40983", "CVE-2024-40984", "CVE-2024-40987", "CVE-2024-40988", "CVE-2024-40990", "CVE-2024-40994", "CVE-2024-40995", "CVE-2024-41000", "CVE-2024-41002", "CVE-2024-41004", "CVE-2024-41005", "CVE-2024-41006", "CVE-2024-41007", "CVE-2024-41027", "CVE-2024-41034", "CVE-2024-41035", "CVE-2024-41040", "CVE-2024-41041", "CVE-2024-41044", "CVE-2024-41046", "CVE-2024-41047", "CVE-2024-41048", "CVE-2024-41049", "CVE-2024-41055", "CVE-2024-41087", "CVE-2024-41089", "CVE-2024-41092", "CVE-2024-41093", "CVE-2024-41095", "CVE-2024-41097", "CVE-2024-42068", "CVE-2024-42070", "CVE-2024-42076", "CVE-2024-42077", "CVE-2024-42080", "CVE-2024-42082", "CVE-2024-42084", "CVE-2024-42085", "CVE-2024-42086", "CVE-2024-42087", "CVE-2024-42089", "CVE-2024-42090", "CVE-2024-42092", "CVE-2024-42093", "CVE-2024-42094", "CVE-2024-42095", "CVE-2024-42096", "CVE-2024-42097", "CVE-2024-42098", "CVE-2024-42101", "CVE-2024-42102", "CVE-2024-42104", "CVE-2024-42105", "CVE-2024-42106", "CVE-2024-42109", "CVE-2024-42115", "CVE-2024-42119", "CVE-2024-42120", "CVE-2024-42121", "CVE-2024-42124", "CVE-2024-42127", "CVE-2024-42130", "CVE-2024-42131", "CVE-2024-42137", "CVE-2024-42140", "CVE-2024-42145", "CVE-2024-42148", "CVE-2024-42152", "CVE-2024-42153", "CVE-2024-42154", "CVE-2024-42157", "CVE-2024-42161", "CVE-2024-42223", "CVE-2024-42224", "CVE-2024-42225", "CVE-2024-42229", "CVE-2024-42232", "CVE-2024-42236", "CVE-2024-42240", "CVE-2024-42244", "CVE-2024-42247");
  script_tag(name:"creation_date", value:"2024-09-19 04:07:37 +0000 (Thu, 19 Sep 2024)");
  script_version("2024-10-03T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-10-03 05:05:33 +0000 (Thu, 03 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-05 17:46:27 +0000 (Thu, 05 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-7019-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7019-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7019-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-xilinx-zynqmp' package(s) announced via the USN-7019-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ziming Zhang discovered that the DRM driver for VMware Virtual GPU did not
properly handle certain error conditions, leading to a NULL pointer
dereference. A local attacker could possibly trigger this vulnerability to
cause a denial of service. (CVE-2022-38096)

Gui-Dong Han discovered that the software RAID driver in the Linux kernel
contained a race condition, leading to an integer overflow vulnerability. A
privileged attacker could possibly use this to cause a denial of service
(system crash). (CVE-2024-23307)

Chenyuan Yang discovered that the CEC driver driver in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2024-23848)

It was discovered that a race condition existed in the Bluetooth subsystem
in the Linux kernel when modifying certain settings values through debugfs.
A privileged local attacker could use this to cause a denial of service.
(CVE-2024-24857, CVE-2024-24858, CVE-2024-24859)

Bai Jiaju discovered that the Xceive XC4000 silicon tuner device driver in
the Linux kernel contained a race condition, leading to an integer overflow
vulnerability. An attacker could possibly use this to cause a denial of
service (system crash). (CVE-2024-24861)

Chenyuan Yang discovered that the Unsorted Block Images (UBI) flash device
volume management subsystem did not properly validate logical eraseblock
sizes in certain situations. An attacker could possibly use this to cause a
denial of service (system crash). (CVE-2024-25739)

Chenyuan Yang discovered that the USB Gadget subsystem in the Linux kernel
did not properly check for the device to be enabled before writing. A local
attacker could possibly use this to cause a denial of service.
(CVE-2024-25741)

Benedict Schluter, Supraja Sridhara, Andrin Bertschi, and Shweta Shinde
discovered that an untrusted hypervisor could inject malicious #VC
interrupts and compromise the security guarantees of AMD SEV-SNP. This flaw
is known as WeSee. A local attacker in control of the hypervisor could use
this to expose sensitive information or possibly execute arbitrary code in
the trusted execution environment. (CVE-2024-25742)

It was discovered that the JFS file system contained an out-of-bounds read
vulnerability when printing xattr debug information. A local attacker could
use this to cause a denial of service (system crash). (CVE-2024-40902)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM32 architecture,
 - ARM64 architecture,
 - M68K architecture,
 - MIPS architecture,
 - PowerPC architecture,
 - RISC-V architecture,
 - SuperH RISC architecture,
 - User-Mode Linux (UML),
 - x86 architecture,
 - Block layer subsystem,
 - Cryptographic API,
 - Accessibility subsystem,
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-xilinx-zynqmp' package(s) on Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1035-xilinx-zynqmp", ver:"5.15.0-1035.39", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx-zynqmp", ver:"5.15.0.1035.39", rls:"UBUNTU22.04 LTS"))) {
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
