# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107304");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-04-11 16:48:58 +0200 (Wed, 11 Apr 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Gather Hardware Information (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_exclude_keys("win/lsc/disable_win_cmd_exec");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based information gathering of the hardware
  configuration from a Windows host.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

SCRIPT_DESC = "Gather Hardware Information (Windows SMB Login)";

include("host_details.inc");
include("smb_nt.inc");
include("powershell_func.inc");

if(is_win_cmd_exec_disabled())
  exit(0);

# -- Get the CPU information -- #
# nb: Make sure to update the header variable below if adding new fields here.
# nb: Without DeviceID it is still returned in the query response so explicitly adding it here
# nb: Some WMI implementations (e.g. on Win XP) doesn't provide "NumberOfCores" so checking first if its included in the response.
processor_infos = powershell_wmi_query(classname:"Win32_Processor");
if( processor_infos && "NumberOfCores" >< processor_infos[0] ) {
  processor_infos = powershell_wmi_query( classname:"Win32_Processor", properties:"DeviceID,Name,NumberOfCores");
} else if( processor_infos ) {
  processor_infos = powershell_wmi_query( classname:"Win32_Processor", properties:"DeviceID,Name");
}

cpunumber = 0;
cpus      = make_array();

if( processor_infos ) {

  # n.b. We need to remove " that are added around the fields by the command
  processor_infos = str_replace( string:processor_infos, find:'"', replace:"" );

  info_list = split( processor_infos, keep:FALSE );

  foreach info( info_list ) {

    cpunumber++;

    info_split = split( info, sep:";", keep:FALSE );

    proc_name = info_split[1];
    num_cores = int( info_split[2] );
    if( ! num_cores )
      num_cores = 1;

    if( isnull( cpus[proc_name] ) ) {
      cpus[proc_name] = num_cores;
    } else {
      cpus[proc_name] += num_cores;
    }
  }
}

# -- Get the systems architecture -- #
# nb: Make sure to update the foreach loop below if adding new fields here
# nb: Some WMI implementations doesn't provide the "OSArchitecture" info within
# Win32_OperatingSystem so checking first if its included in the response and
# use a fallback to a possible Arch gathered via SMB.
arch_infos = powershell_wmi_query(classname:"Win32_OperatingSystem");
arch       = "";
if( arch_infos && "OSArchitecture" >< arch_infos[0] ) {
  arch_infos = powershell_wmi_query(classname:"Win32_OperatingSystem", properties:"OSArchitecture");
} else {
  _arch = get_kb_item( "SMB/Windows/Arch" );
  if( _arch && _arch == "x64" ) {
    arch = "64-bit";
  } else if( _arch && _arch == "x86" ) {
    arch = "32-bit";
  } else {
    arch = "unknown";
  }
  arch_infos = "";
  set_kb_item( name:"wmi/login/arch", value:arch );
}

if( arch_infos ) {

  info_list = split( arch_infos, keep:FALSE );

  foreach info( info_list ) {

    arch = info;
    set_kb_item( name:"wmi/login/arch", value:arch );
  }
}

# -- Get the PCI information -- #
# nb: Make sure to update the foreach loop below if adding new fields here
pci_devices = powershell_wmi_query(classname:"Win32_PNPEntity", class_args:"-Filter \" + raw_string(0x22) + "DeviceID LIKE '%PCI\\VEN_%'" + '\\"', properties:"DeviceID, Manufacturer, Name"); #_156  8086&DEV_156
if( pci_devices ) {

  # n.b. We need to remove " that are added around the fields by the command
  pci_devices = str_replace( string:pci_devices, find:'"', replace:"" );

  deviceid = 0;
  pci_list = split( pci_devices, keep:FALSE );

  foreach pcidevice( pci_list ) {

    # nb: Sometimes we get something like 2: '' back from the WMI query so also continue in such cases.
    if( pcidevice == "" )
      continue;

    deviceid++;
    pcidevice_split = split( pcidevice, sep:";", keep:FALSE );
    manufacturer    = pcidevice_split[1];
    name            = pcidevice_split[2];

    set_kb_item( name:"ssh_or_wmi/login/pci_devices/available", value:TRUE );
    set_kb_item( name:"wmi/login/pci_devices/available", value:TRUE );
    set_kb_item( name:"wmi/login/pci_devices/device_ids", value:deviceid );

    # nb: Keep "slot, vendor and device" parts of the KB name the same like in the output of lspci -vmm on linux (see gb_gather_hardware_info_ssh_login.nasl)
    set_kb_item( name:"wmi/login/pci_devices/" + deviceid + "/slot", value:deviceid );
    set_kb_item( name:"wmi/login/pci_devices/" + deviceid + "/vendor", value:manufacturer );
    set_kb_item( name:"wmi/login/pci_devices/" + deviceid + "/device", value:name );
  }
}

# -- Get the memory information -- #
# nb: Make sure to update the foreach loop below if adding new fields here
memory  = powershell_wmi_query(classname:"Win32_Computersystem", properties:"Name, TotalPhysicalMemory");
meminfo = "";
if( memory ) {

  # n.b. We need to remove " that are added around the fields by the command
  memory = str_replace( string:memory, find:'"', replace:"" );

  mem_list = split( memory, keep:FALSE );

  foreach mem( mem_list ) {

    mem_split = split( mem, sep:";", keep:FALSE );
    # nb: We're getting a "data" back here. Using int() to convert it to an integer might cause an integer overflow as we have an uint64 here
    # GOS 5.0 / GVM 10 will fix this so working around this by using a byte for now when getting a negative integer
    memtotal  = mem_split[1];
    _memtotal = int( memtotal );

    if( _memtotal < 0 ) {
      meminfo = memtotal + " B";
    } else if( _memtotal > 0 ) {
      meminfo = ( _memtotal / 1024 ) + " kB";
    } else {
      meminfo = "unknown";
    }
  }
}

# -- Get the network interfaces information -- #
# nb: Make sure to update the foreach loop below if adding new fields here
pscmd = "Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Select-Object Description, Index, @{Name='IPAddress'; Expression={($_.IPAddress -join ',')}}, MACAddress | ConvertTo-Csv -NoTypeInformation -Delimiter ';' | Select-Object -Skip 1";
addresses = powershell_cmd(cmd:pscmd);
num_ifaces = 0;
host_ip    = get_host_ip();
if( addresses ) {

  # n.b. We need to remove " that are added around the fields by the command
  addresses = str_replace( string:addresses, find:'"', replace:"" );
  addr_list = split( addresses, keep:FALSE );
  foreach address( addr_list ) {

    iface_ipstr = "";
    addr_split  = split( address, sep:";", keep:FALSE );
    iface_name  = addr_split[0]; # Description

    # IPAddress is coming in with a form like:
    # ifacename1;0;127.0.0.1;127.0.0.2;mac
    # ifacename2;1;127.0.0.3;mac
    # RAS Async Adapter;2;;mac
    # WAN Miniport (IPv6);5;;
    # so we need to build our IP address here based on the length of the list
    for( i = 2; i < max_index( addr_split ) - 1; i++ ) {
      if( addr_split[i] != "" )
        iface_ipstr += addr_split[i] + ";";
    }

    iface_mac = addr_split[max_index( addr_split ) - 1]; # MACAddress

    # Verification for the MAC address syntax
    iface_mac = eregmatch( pattern:"([0-9a-fA-F:]{17})", string:iface_mac );
    if( ! isnull( iface_mac ) ) {

      num_ifaces++;
      replace_kb_item( name:"wmi/login/net_iface/num_ifaces", value:num_ifaces );

      if( host_ip >< iface_ipstr ) {

        register_host_detail( name:"MAC", value:iface_mac[1], desc:SCRIPT_DESC );
        set_kb_item( name:"wmi/login/net_iface/" + num_ifaces + "/iface_mac", value:iface_mac[1] );
        if( iface_name != "" ) {
          target_nic = iface_name;
          register_host_detail( name:"NIC", value:iface_name, desc:SCRIPT_DESC );
          set_kb_item( name:"wmi/login/net_iface/" + num_ifaces + "/iface_name", value:iface_name );
          if( strlen( iface_ipstr ) > 0 ) {
            register_host_detail( name:"NIC_IPS", value:iface_ipstr, desc:SCRIPT_DESC );
            set_kb_item( name:"wmi/login/net_iface/" + num_ifaces + "/iface_ips", value:iface_ipstr );
          }
        }
      }

      if( iface_name != "" && iface_name != target_nic ) {
        set_kb_item( name:"wmi/login/net_iface/" + num_ifaces + "/iface_mac", value:iface_mac[1] );
        set_kb_item( name:"wmi/login/net_iface/" + num_ifaces + "/iface_name", value:iface_name );
        set_kb_item( name:"wmi/login/net_iface/" + num_ifaces + "/iface_ips", value:iface_ipstr );
        register_host_detail( name:"MAC-Ifaces", value:iface_name + '|' + iface_mac[1] + '|' + iface_ipstr, desc:SCRIPT_DESC );
      }
    } else {
      if( iface_mac != "" && iface_name != "" ) {
        register_host_detail( name:"BROKEN_MAC-Iface", value:iface_name + '|' + iface_mac + '|' + iface_ipstr, desc:SCRIPT_DESC );
      }
    }
  }
}

if( num_ifaces > 0 ) {
  # -- Get the full network interfaces information -- #
  full_netinfo = powershell_wmi_query(classname:"Win32_NetworkAdapterConfiguration");
}
netinfo = "";

if( full_netinfo )
  netinfo = full_netinfo;

# -- Store results in the host details DB -- #
if( cpunumber ) {
  cpu_str = "";
  foreach cputype( keys( cpus ) ) {
    if( cpu_str != "" ) {
      cpu_str += '\n';
    }
    cpu_str += string( cpus[cputype], " ", cputype );
  }
  register_host_detail( name:"cpuinfo", value:cpu_str, desc:SCRIPT_DESC );
}

if( arch != "" ) {
  register_host_detail( name:"archinfo", value:arch, desc:SCRIPT_DESC );
}

if( meminfo != "" ) {
  register_host_detail( name:"meminfo", value:meminfo, desc:SCRIPT_DESC );
}

if( netinfo != "" ) {
  register_host_detail( name:"netinfo", value:netinfo, desc:SCRIPT_DESC );
}

exit( 0 );
