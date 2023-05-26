#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# Checks based on the ISIS-MIB.
#
# Copyright (C) 2022 Curtis Bowden <curtis.bowden@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Example excerpt from SNMP data:
# snmpwalk of .1.3.6.1.4.1.2636.3.44.1.2.2.1.3
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.0.0.nh = Gauge32: 79 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.0.0.fw = Gauge32: 99 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.0.1.nh = Gauge32: 80 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.0.1.fw = Gauge32: 99 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.1.0.nh = Gauge32: 80 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.1.0.fw = Gauge32: 99 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.1.1.nh = Gauge32: 80 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.1.1.fw = Gauge32: 99 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.2.0.nh = Gauge32: 80 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.2.0.fw = Gauge32: 99 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.2.1.nh = Gauge32: 80 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.2.1.fw = Gauge32: 99 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.3.0.nh = Gauge32: 80 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.3.0.fw = Gauge32: 99 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.3.1.nh = Gauge32: 80 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.3.1.fw = Gauge32: 99 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.4.0.nh = Gauge32: 80 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.4.0.fw = Gauge32: 99 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.4.1.nh = Gauge32: 80 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.4.1.fw = Gauge32: 99 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.5.0.nh = Gauge32: 79 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.5.0.fw = Gauge32: 99 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.5.1.nh = Gauge32: 80 percent
# JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree.5.1.fw = Gauge32: 99 percent
# 
# snmpwalk of .1.3.6.1.4.1.2636.3.1.13.1.5.7
# JUNIPER-MIB::jnxOperatingDescr.7.1.0.0 = STRING: FPC: MPC4E 3D 32XGE @ 0/*/*
# JUNIPER-MIB::jnxOperatingDescr.7.2.0.0 = STRING: FPC: MPC3E NG PQ & Flex Q @ 1/*/*
# JUNIPER-MIB::jnxOperatingDescr.7.4.0.0 = STRING: FPC: MPCE Type 3 3D @ 3/*/*
# JUNIPER-MIB::jnxOperatingDescr.7.5.0.0 = STRING: FPC: MPC3E NG PQ & Flex Q @ 4/*/*
# JUNIPER-MIB::jnxOperatingDescr.7.6.0.0 = STRING: FPC: MPC7E 3D MRATE-12xQSFPP-XGE-XLGE-CGE @ 5/*/*
# JUNIPER-MIB::jnxOperatingDescr.7.8.0.0 = STRING: FPC: MPC7E 3D MRATE-12xQSFPP-XGE-XLGE-CGE @ 7/*/*
# JUNIPER-MIB::jnxOperatingDescr.7.9.0.0 = STRING: FPC: MPCE Type 3 3D @ 8/*/*
# JUNIPER-MIB::jnxOperatingDescr.7.10.0.0 = STRING: FPC: MPCE Type 3 3D @ 9/*/*
# JUNIPER-MIB::jnxOperatingDescr.7.11.0.0 = STRING: FPC: MPCE Type 3 3D @ 10/*/*
# JUNIPER-MIB::jnxOperatingDescr.7.12.0.0 = STRING: FPC: MPCE Type 1 3D @ 11/*/*

import re

from cmk.base.plugins.agent_based.agent_based_api.v1 import (
    register,
    SNMPTree,
    exists,
    Service,
    Result,
    State,
)


def parse_pfemem(string_table):
    parsed = {}
    pfememory = {}
    mem = []
    i = 0
    nh_free = []
    fw_free = []

    for items in string_table:
        pfememory[i] = {}
        pfememory[i]['mem'] = []
        pfememory[i]['card'] = ''
        for item in items:
            if item.isnumeric() == True:
                mem.append(item)
            elif re.search('FPC', item) :
                pfememory[i]['card'] = item
                pfememory[i]['mem'] = mem
                mem = []
                i += 1

    for key,values in pfememory.items():

        item = f"{values['card']} Free Memory"
        parsed[item] = {}
        parsed[item]['card'] = values['card']
        #parsed[item]['fw_free'] = ''
        #print(values['mem'])
        for i in values['mem']:
            if len(values['mem']) == 2:
                    if ((values['mem'].index(i) + 1) % 2 !=0) and i not in nh_free:
                        nh_free.append(i)
                        #print(f"{values['mem'].index(i)} - {i}")
                    elif ((values['mem'].index(i) + 1) % 2 == 0) and i not in fw_free:
                        fw_free.append(i)
                        #print(f"{values['mem'].index(i)} - {i}")
                    elif ((i == values['mem'][0] and i == values['mem'][1]) and
                          (i not in fw_free)):
                        fw_free.append(i)

            elif len(values['mem']) == 4:
                if ((i == values['mem'][3] and i == values['mem'][2]) or
                    (i == values['mem'][0] and i == values['mem'][1]) or
                    (i == values['mem'][0] and i == values['mem'][3]) and
                    (i not in nh_free or i not in fw_free)):
                    nh_free.append(i)
                    fw_free.append(i)
                elif values['mem'].index(i) == 0 or values['mem'].index(i) == 2:
                    nh_free.append(i)
                elif values['mem'].index(i) == 1 or values['mem'].index(i) == 3:
                    fw_free.append(i)

        #print(nh_free)
        #print(fw_free)
        if len(nh_free) == 2:
            parsed[item]['nh_free1'] = nh_free[0]
            parsed[item]['nh_free2'] = nh_free[1]
        elif nh_free:
            parsed[item]['nh_free1'] = nh_free[0]

        if len(fw_free) == 2:
            parsed[item]['fw_free1'] = fw_free[0]
            parsed[item]['fw_free2'] = fw_free[1]
        elif fw_free:
            parsed[item]['fw_free1'] = fw_free[0]
        
        nh_free = []
        fw_free = []
            
    #print(parsed)

    return parsed



register.snmp_section(
    name='pfememory',
    detect=exists('.1.3.6.1.4.1.2636.3'),
    fetch=SNMPTree(
        base='.1.3.6.1.4.1.2636.3',
        oids=[
            '1.13.1.5.7',  # JUNIPER-MIB::jnxOperatingDescr
            '44.1.2.2.1.3', # JUNIPER-PFE-MIB::jnxPfeMemoryForwardingPercentFree
        ],
    ),
    parse_function=parse_pfemem,
)


def discover_pfememory(section):
    #print(f'this {section}')
    
    for service in section.keys():
        yield Service(item=service)



def check_pfememory(item, section):
    if item not in section:
        return
    nh_free1 = int(section[item]['nh_free1'])
    fw_free1 = int(section[item]['fw_free1'])
    card = section[item]['card']
    details = f'MIC 0  NH Free {nh_free1}, MIC 0 FW Free {fw_free1}'
    
    # Yield for 1st mic
    if nh_free1 <= 10:
        yield Result(state=State.CRIT, summary=f'NH Free Memory on MIC 0 is very low at {nh_free1}', details=details)
    if fw_free1 <= 10:
        yield Result(state=State.CRIT, summary=f'FW Free Memory on MIC 0 is very low at {fw_free1}', details=details)
    if nh_free1 <= 15:
        yield Result(state=State.WARN, summary=f'NH Free Memory on MIC 0 is low at {nh_free1}', details=details)
    if fw_free1 <= 15:
        yield Result(state=State.WARN, summary=f'FW Free Memory on MIC 0 is low at {fw_free1}', details=details)
    if nh_free1 > 15:
        yield Result(state=State.OK, summary=f'NH Free Memory on MIC 0 is normal at {nh_free1}', details=details)
    if fw_free1 > 15:
        yield Result(state=State.OK, summary=f'FW Free Memory on MIC 0 is normal at {fw_free1}', details=details)

    # Check if second mic is present
    if len(section[item]) >= 4:
    #if section[item]['nh_free2'] or section[item]['fw_free2']:
        nh_free2 = int(section[item]['nh_free2'])
        fw_free2 = int(section[item]['fw_free2'])

        details = f'MIC 0  NH Free {nh_free1}, MIC 0 FW Free {fw_free1}, MIC 1 NH Free {nh_free2}, MIC 1 FW Free {fw_free2}'

        # Yield for 2nd mic if present
        if nh_free2 <= 10:
            yield Result(state=State.CRIT, summary=f'NH Free Memory on MIC 1 is very low at {nh_free2}', details=details)
        if fw_free2 <= 10:
            yield Result(state=State.CRIT, summary=f'FW Free Memory on MIC 1 is very low at {fw_free2}', details=details)
        if nh_free2 <= 15:
            yield Result(state=State.WARN, summary=f'NH Free Memory on MIC 1 is low at {nh_free2}', details=details)
        if fw_free2 <= 15:
            yield Result(state=State.WARN, summary=f'FW Free Memory on MIC 1 is low at {fw_free2}', details=details)
        if nh_free2 > 15:
            yield Result(state=State.OK, summary=f'NH Free Memory on MIC 1 is normal at {nh_free2}', details=details)
        if fw_free2 > 15:
            yield Result(state=State.OK, summary=f'FW Free Memory on MIC 1 is normal at {fw_free2}', details=details)
    
register.check_plugin(
    name='pfememory',
    service_name='PFE %s Memory Utilization',
    discovery_function=discover_pfememory,
    check_function=check_pfememory,
)
